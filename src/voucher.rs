//! Voucher accounting: allowance, success proof, bond-addressed obligations.
//!
//! Integer-only mirror of the account circuit. The parameters are part of the
//! rulebook-signed standing policy ([`crate::standing::VoucherParams`]); nothing here
//! is configurable at call time. Obligations are addressed by tags derived from the
//! bond secret, so no server learns which two members share a bond.
use crate::Error;
use crate::poseidon::{hash, integer, limbs};
use crate::standing::{Policy, Q, ROLES, State};

/// Role classes with their own allowance clamp.
pub const MEMBER: u8 = 0;
/// Administrators.
pub const ADMIN: u8 = 1;
/// Roots.
pub const ROOT: u8 = 2;

/// Obligation kinds posted through the bond.
pub const SUCCESS: u8 = 1;
/// The vouchee received a punishment.
pub const PUNISHED: u8 = 2;
/// The vouchee's own vouchee succeeded.
pub const REWARD: u8 = 3;

const TAG_OBLIGATION: u64 = 60;
const TAG_BOND_COMMIT: u64 = 61;
const TAG_BOND_KEY: u64 = 62;
const TAG_MEMBER: u64 = 63;
const TAG_ENTRY: u64 = 64;
const TAG_ISSUE_NULLIFIER: u64 = 65;

/// Most allowance units one issue presentation can claim (its fixed nullifier output).
pub const ISSUE_UNITS: u64 = 16;

/// The voucher part of the committed account state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Day (never zero) of the account's own success proof; zero until then.
    pub proven: u64,
    /// Vouchers spent on admissions whose vouchee has not yet proven success.
    pub away: u64,
    /// Vouchers reserved by links that are still open (made at link creation by an issue
    /// presentation, released by expiry, revocation or decline, moved to `away` by an
    /// actual admission).
    pub reserved: u64,
    /// Vouchers lost for good (overshoot of concurrent admissions).
    pub lost: u64,
    /// Permanent reward bonus.
    pub bonus: u64,
    /// Success obligations consumed as a sponsor.
    pub returned: u64,
    /// Distinct qualifying answered conversations.
    pub answers: u64,
}

/// The pool cap in whole open waves for a standing state.
pub fn cap(state: &State, p: &Policy) -> u64 {
    state.cap(p)
}

/// Voucher limit: clamp(slope x cap, min, max) + bonus - lost, never below zero.
/// An unproven member has none; administrators and roots hold theirs by role.
pub fn limit(p: &Policy, role: u8, account: &Account, cap: u64) -> Result<u64, Error> {
    let r = usize::from(role);
    if r >= ROLES {
        return Err(Error::InvalidInput);
    }
    if role == MEMBER && account.proven == 0 {
        return Ok(0);
    }
    let v = &p.params.voucher;
    let base = ((u128::from(v.slope_q[r]) * u128::from(cap)) >> 16) as u64;
    let clamped = base.clamp(v.min[r], v.max[r]);
    Ok((clamped + account.bonus).saturating_sub(account.lost))
}

/// Vouchers still available to hand out: the limit less admitted and reserved ones.
pub fn remaining(p: &Policy, role: u8, account: &Account, cap: u64) -> Result<u64, Error> {
    Ok(limit(p, role, account, cap)?
        .saturating_sub(account.away)
        .saturating_sub(account.reserved))
}

/// A pool cap at or below the brake value counts as braked.
pub fn braked(p: &Policy, cap: u64) -> bool {
    cap <= p.params.voucher.brake_cap
}

/// The vouchee's success proof, public parameters from the policy.
pub fn success_ready(p: &Policy, state: &State, account: &Account, punished_received: u64) -> bool {
    let v = &p.params.voucher;
    account.proven == 0
        && state.day.saturating_sub(state.joined) >= v.days
        && !braked(p, state.cap(p))
        && punished_received <= v.max_punished
        && account.answers >= v.k
}

/// Weight (Q16) a vouchee's punishment adds to the sponsor: one over the limit at issuance.
pub fn punish_weight(limit_at_issuance: u64) -> u64 {
    Q.div_ceil(limit_at_issuance.max(1))
}

/// Reward bonus after one more successful grand-vouchee, capped by the policy.
pub fn rewarded(p: &Policy, bonus: u64) -> u64 {
    (bonus + 1).min(p.params.voucher.reward_cap).max(bonus)
}

fn domain_hash(domain: &[u8; 32], tag: u64, rest: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    let mut values = vec![*domain, integer(tag)];
    values.extend_from_slice(rest);
    hash(&values)
}

/// Commitment to a bond secret kept in the vouchee's account state.
pub fn bond_commit(domain: &[u8; 32], bond: &[u8; 32]) -> Result<[u8; 32], Error> {
    domain_hash(domain, TAG_BOND_COMMIT, &limbs(bond))
}

/// Key of the bond in the sponsor's private bond map.
pub fn bond_key(domain: &[u8; 32], bond: &[u8; 32]) -> Result<[u8; 32], Error> {
    domain_hash(domain, TAG_BOND_KEY, &limbs(bond))
}

/// Tag of the n-th obligation of a kind; the only address a server ever sees.
pub fn obligation_tag(
    domain: &[u8; 32],
    bond: &[u8; 32],
    kind: u8,
    n: u64,
) -> Result<[u8; 32], Error> {
    let b = limbs(bond);
    domain_hash(
        domain,
        TAG_OBLIGATION,
        &[b[0], b[1], integer(u64::from(kind)), integer(n)],
    )
}

/// Pseudonymous member tag kept as the sponsor field of the vouchee's state.
pub fn member_tag(
    domain: &[u8; 32],
    community: &[u8; 32],
    member: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let (c, m) = (limbs(community), limbs(member));
    domain_hash(domain, TAG_MEMBER, &[c[0], c[1], m[0], m[1]])
}

/// Per-unit issue nullifier: a PRF of the member's owner secret over community, epoch and
/// allowance unit index. Unlinkable to the member and to other epochs; a repeat inside an
/// epoch is a reuse of that unit of the allowance.
pub fn issue_nullifier(
    domain: &[u8; 32],
    owner_secret: &[u8; 32],
    community: &[u8; 32],
    epoch: u64,
    unit: u64,
) -> Result<[u8; 32], Error> {
    let (s, c) = (limbs(owner_secret), limbs(community));
    domain_hash(
        domain,
        TAG_ISSUE_NULLIFIER,
        &[s[0], s[1], c[0], c[1], integer(epoch), integer(unit)],
    )
}

/// What the sponsor remembers about one bond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The sponsor's limit when the voucher was spent (at least one).
    pub limit: u64,
    /// The success obligation was consumed.
    pub done: bool,
    /// The admission overshot the allowance and was lost for good.
    pub overshoot: bool,
    /// Punishment obligations consumed.
    pub punished_seen: u64,
    /// Reward obligations consumed.
    pub rewards_seen: u64,
}

impl Entry {
    /// The map leaf value.
    pub fn digest(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        domain_hash(
            domain,
            TAG_ENTRY,
            &[
                integer(self.limit),
                integer(u64::from(self.done)),
                integer(u64::from(self.overshoot)),
                integer(self.punished_seen),
                integer(self.rewards_seen),
            ],
        )
    }
}

impl Account {
    /// The sponsor spends one voucher on an actual admission. Returns the bond entry.
    pub fn admit(&mut self, p: &Policy, role: u8, cap: u64) -> Result<Entry, Error> {
        let limit = limit(p, role, self, cap)?;
        let overshoot = limit.saturating_sub(self.away) == 0;
        // An admission consumes one reserved unit of an open link when there is one.
        self.reserved = self.reserved.saturating_sub(1);
        if overshoot {
            self.lost += 1;
        } else {
            self.away += 1;
        }
        Ok(Entry {
            limit: limit.max(1),
            done: false,
            overshoot,
            punished_seen: 0,
            rewards_seen: 0,
        })
    }

    /// A link of `units` uses is created: the issue presentation reserves them. Refused above
    /// the remaining allowance.
    pub fn reserve(&mut self, p: &Policy, role: u8, cap: u64, units: u64) -> Result<(), Error> {
        if units == 0 || units > remaining(p, role, self, cap)? {
            return Err(Error::InvalidInput);
        }
        self.reserved += units;
        Ok(())
    }

    /// Unused uses of a link expired, were revoked or declined: the units return.
    pub fn release(&mut self, units: u64) -> Result<(), Error> {
        if units == 0 || units > self.reserved {
            return Err(Error::InvalidInput);
        }
        self.reserved -= units;
        Ok(())
    }

    /// The vouchee proved success: the voucher returns unless it was lost.
    pub fn consume_success(&mut self, entry: &mut Entry) -> Result<(), Error> {
        if entry.done {
            return Err(Error::InvalidInput);
        }
        entry.done = true;
        if !entry.overshoot {
            self.away = self.away.checked_sub(1).ok_or(Error::InvalidInput)?;
        }
        self.returned += 1;
        Ok(())
    }

    /// The vouchee was punished: the sponsor takes the fractional weight.
    pub fn consume_punished(&self, entry: &mut Entry, state: &mut State) -> Result<(), Error> {
        entry.punished_seen += 1;
        state.pr += punish_weight(entry.limit);
        Ok(())
    }

    /// The vouchee's own vouchee succeeded.
    pub fn consume_reward(&mut self, p: &Policy, entry: &mut Entry) {
        entry.rewards_seen += 1;
        self.bonus = rewarded(p, self.bonus);
    }
}
