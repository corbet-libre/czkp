//! Standing v5 policy tables and integer state transitions.
//!
//! This is the single owner function for the derived tables: the trust table, the
//! decay tables and the clean-conversation factor are computed here, deterministically
//! and in integers only, from the community's tunable parameters. The digest of the
//! parameters and tables is the value the rulebook signs and the circuits bind. Clients
//! never compute tables; the circuits check them against that digest.
//!
//! Punishments given and received weigh 1 each (decided), so those weights are
//! constants, not parameters. All quantities are Q16 fixed point unless noted.
use crate::{Error, poseidon};

/// One in Q16.
pub const Q: u64 = 1 << 16;
/// Entries in the trust table (excess punishments 0 to 8 in steps of 1/8).
pub const TRUST_ENTRIES: usize = 65;
/// Padded length of each decay table.
pub const TABLE_PAD: usize = 64;
const ONE: u128 = 1 << 60;
/// round(ln 2 * 2^60).
const LN2: u128 = 799_144_290_325_165_979;
/// Field-list tag of the standing policy digest.
const TAG: u64 = 41;

/// Tunable community parameters (rulebook-signed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Newcomer cap in open waves on day one.
    pub c0: u64,
    /// Starter loan half-life in days.
    pub h_a: u64,
    /// Goodwill half-life in days.
    pub h_g: u64,
    /// Clean conversations per half-life of punishment memory.
    pub n_half: u64,
    /// Length of the clean-conversation record.
    pub n_c: u64,
    /// Goodwill for answering a wave (Q16).
    pub e_q: u64,
    /// Maximum reach (open waves above one).
    pub r_max: u64,
    /// Reach ceiling growth per day of membership.
    pub r_age: u64,
    /// Largest veteran offset (Q16, below one punishment).
    pub c_max_q: u64,
    /// Clean-conversation record for the full veteran offset.
    pub c_vet: u64,
    /// Days of membership for the full veteran offset.
    pub age_vet: u64,
    /// Extra goodwill per answer in the boost window (Q16).
    pub boost_q: u64,
    /// Length of the boost window in days.
    pub boost_days: u64,
    /// Logistic slope of the trust curve (Q16).
    pub slope_q: u64,
    /// Excess punishments at which trust halves (Q16).
    pub mid_q: u64,
    /// Reach per unit of goodwill (Q16), a signed epoch input.
    pub kappa_q: u64,
    /// Starter loan used per unanswered wave (Q16), a signed epoch input.
    pub loan_use_q: u64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            c0: 3,
            h_a: 14,
            h_g: 14,
            n_half: 25,
            n_c: 60,
            e_q: Q / 4,
            r_max: 40,
            r_age: 2,
            c_max_q: 52_428,
            c_vet: 30,
            age_vet: 60,
            boost_q: Q,
            boost_days: 30,
            slope_q: 4 * Q,
            mid_q: 49_152,
            kappa_q: 2 * Q,
            loan_use_q: Q / 4,
        }
    }
}

impl Params {
    /// Safe ranges every community setting must stay inside.
    pub fn validate(&self) -> Result<(), Error> {
        let ok = |v: u64, lo: u64, hi: u64| (lo..=hi).contains(&v);
        let checks = [
            ok(self.c0, 1, 16),
            ok(self.h_a, 1, 64),
            ok(self.h_g, 1, 64),
            ok(self.n_half, 5, 200),
            ok(self.n_c, 10, 200),
            ok(self.e_q, 0, Q),
            ok(self.r_max, 1, 200),
            ok(self.r_age, 0, 16),
            ok(self.c_max_q, 0, 58_982),
            ok(self.c_vet, 1, 200),
            ok(self.age_vet, 1, 365),
            ok(self.boost_q, 0, 2 * Q),
            ok(self.boost_days, 0, 90),
            ok(self.slope_q, Q, 8 * Q),
            ok(self.mid_q, Q / 4, 3 * Q),
            ok(self.kappa_q, Q / 2, 6 * Q),
            ok(self.loan_use_q, 1, Q),
        ];
        let good = checks.iter().all(|c| *c);
        if good {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}

/// e^(-x) for a Q60 argument, returned in Q60.
fn exp_neg(x: u128) -> u128 {
    let (n, r) = (x / LN2, x % LN2);
    // The largest valid argument is 64 (slope 8 times 8), so n stays below 100 and the
    // shift below is always defined.
    let (mut sum, mut term) = (ONE, ONE);
    for k in 1..=40u128 {
        term = ((term * r) >> 60) / k;
        sum = if k & 1 == 1 { sum - term } else { sum + term };
    }
    sum >> n
}

fn clean_factor(n_half: u64) -> u64 {
    (exp_neg(LN2 / u128::from(n_half)) >> 44) as u64
}

fn decay_table(h: u64) -> [u64; TABLE_PAD] {
    let mut out = [0; TABLE_PAD];
    for r in 0..h {
        let x = LN2 * u128::from(r) / u128::from(h);
        out[r as usize] = ((exp_neg(x) + (1 << 43)) >> 44) as u64;
    }
    out
}

fn logistic(t: i128) -> u128 {
    if t >= 0 {
        (ONE << 60) / (ONE + exp_neg(t as u128))
    } else {
        let e = exp_neg(t.unsigned_abs());
        (e << 60) / (ONE + e)
    }
}

fn trust_table(slope_q: u64, mid_q: u64) -> [u64; TRUST_ENTRIES] {
    let f0 = logistic(-((i128::from(slope_q) * i128::from(mid_q)) << 28));
    let den = ONE - f0;
    let mut out = [0; TRUST_ENTRIES];
    for (i, slot) in out.iter_mut().enumerate() {
        let x = i128::from(i as u64 * (Q / 8)) - i128::from(mid_q);
        let t = (i128::from(slope_q) * x) << 28;
        let num = ONE - logistic(t);
        let v = (num * u128::from(Q) * 2 + den) / (2 * den);
        *slot = v.min(u128::from(Q)) as u64;
    }
    out[0] = Q;
    out
}

/// Parameters with every derived table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The tunable parameters.
    pub params: Params,
    /// Per clean conversation multiplier of the punishment memory (Q16).
    pub factor: u64,
    /// Trust by excess punishments in steps of 1/8.
    pub trust: [u64; TRUST_ENTRIES],
    /// Goodwill decay by days modulo the half-life.
    pub g_table: [u64; TABLE_PAD],
    /// Starter loan decay by days modulo the half-life.
    pub a_table: [u64; TABLE_PAD],
}

impl Policy {
    /// The only way to obtain the tables: validate, then derive.
    pub fn derive(params: Params) -> Result<Policy, Error> {
        params.validate()?;
        Ok(Policy {
            params,
            factor: clean_factor(params.n_half),
            trust: trust_table(params.slope_q, params.mid_q),
            g_table: decay_table(params.h_g),
            a_table: decay_table(params.h_a),
        })
    }

    /// Canonical integer list that is hashed into the digest.
    pub fn fields(&self) -> Vec<u64> {
        let p = &self.params;
        let mut out = vec![
            p.c0,
            p.h_a,
            p.h_g,
            p.n_half,
            p.n_c,
            p.e_q,
            p.r_max,
            p.r_age,
            p.c_max_q,
            p.c_vet,
            p.age_vet,
            p.boost_q,
            p.boost_days,
            p.slope_q,
            p.mid_q,
            p.kappa_q,
            p.loan_use_q,
            self.factor,
        ];
        out.extend_from_slice(&self.trust);
        out.extend_from_slice(&self.g_table);
        out.extend_from_slice(&self.a_table);
        out
    }

    /// Poseidon2 digest `hash([domain, 41, fields...])`; the circuit mirrors this list.
    pub fn digest(&self, domain: &[u8; 32]) -> Result<[u8; 32], Error> {
        let mut values = vec![*domain, poseidon::integer(TAG)];
        values.extend(self.fields().into_iter().map(poseidon::integer));
        poseidon::hash(&values)
    }
}

/// Per-member standing state (the part committed in the account).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// Goodwill (Q16).
    pub g: u64,
    /// Starter loan (Q16).
    pub a: u64,
    /// Clean-conversation record (Q16).
    pub c: u64,
    /// Punishments received (Q16).
    pub pr: u64,
    /// Punishments given (Q16).
    pub pg: u64,
    /// Lifetime punishment count.
    pub lc: u64,
    /// Day of the last calendar decay.
    pub day: u64,
    /// Admission day, set by the issuer.
    pub joined: u64,
}

fn decay(x: u64, days: u64, h: u64, table: &[u64; TABLE_PAD]) -> u64 {
    if x == 0 {
        return x;
    }
    let (qd, r) = (days / h, days % h);
    if qd >= 31 {
        return 0;
    }
    (((x >> qd) as u128 * u128::from(table[r as usize])) >> 16) as u64
}

fn mul_up(x: u64, f: u64) -> u64 {
    if x == 0 {
        0
    } else {
        ((u128::from(x) * u128::from(f)).div_ceil(1 << 16)) as u64
    }
}

impl State {
    /// A fresh member admitted on `day` with starter loan `a0_q`.
    pub fn new(day: u64, a0_q: u64) -> State {
        State {
            g: 0,
            a: a0_q,
            c: 0,
            pr: 0,
            pg: 0,
            lc: 0,
            day,
            joined: day,
        }
    }

    /// Calendar decay of goodwill and loan only; punishments never decay by date.
    pub fn advance(&mut self, day: u64, p: &Policy) {
        if day > self.day {
            let d = day - self.day;
            self.g = decay(self.g, d, p.params.h_g, &p.g_table);
            self.a = decay(self.a, d, p.params.h_a, &p.a_table);
            self.day = day;
        }
    }

    fn clean(&mut self, p: &Policy) {
        self.pr = mul_up(self.pr, p.factor);
        self.pg = mul_up(self.pg, p.factor);
        self.c = self.c - self.c / p.params.n_c + Q;
    }

    /// A counterpart-signed Answer on my wave.
    pub fn answer_received(&mut self, p: &Policy) {
        self.g += Q;
        if p.params.boost_q > 0 && self.day - self.joined < p.params.boost_days {
            self.g += p.params.boost_q;
        }
        self.clean(p);
    }

    /// My own Answer on a wave I received.
    pub fn answer_given(&mut self, p: &Policy) {
        self.g += p.params.e_q;
        self.clean(p);
    }

    /// A settled close, silence or punished wave of mine.
    pub fn unanswered(&mut self, p: &Policy) {
        let d = p.params.loan_use_q;
        self.a = self.a.saturating_sub(d);
    }

    /// Group welcome or introduction credit.
    pub fn group_credit(&mut self, credit_q: u64) {
        self.g += credit_q;
    }

    /// A punishment received; `established` when it ended a conversation.
    pub fn punished(&mut self, established: bool) {
        self.pr += Q;
        self.lc += 1;
        if established && self.c >= Q {
            self.c -= Q;
        }
    }

    /// A punishment I gave.
    pub fn punish_given(&mut self) {
        self.pg += Q;
        self.lc += 1;
    }

    fn veteran(&self, p: &Policy) -> u64 {
        let q = &p.params;
        let f = Q
            .min(self.c / q.c_vet)
            .min(((self.day - self.joined) << 16) / q.age_vet);
        (q.c_max_q * f) >> 16
    }

    /// Trust (Q16) from the excess punishments.
    pub fn trust(&self, p: &Policy) -> u64 {
        let ex = i128::from(self.pr) + i128::from(self.pg) - i128::from(self.veteran(p));
        if ex <= 0 {
            return Q;
        }
        let i = ((ex * 8 + i128::from(Q / 2)) >> 16).min(64);
        p.trust[i as usize]
    }

    /// Reach (Q16), the open waves above the first.
    pub fn reach(&self, p: &Policy) -> u64 {
        let q = &p.params;
        let r = ((u128::from(q.kappa_q) * u128::from(self.g)) >> 16) as u64 + self.a;
        let ceiling = (q.c0 - 1 + q.r_age * (self.day - self.joined)) << 16;
        r.min(q.r_max << 16).min(ceiling)
    }

    /// Size of the shared pool of pending first contacts; never below one.
    pub fn cap(&self, p: &Policy) -> u64 {
        1 + ((u128::from(self.trust(p)) * u128::from(self.reach(p)) + (1 << 31)) >> 32) as u64
    }
}
