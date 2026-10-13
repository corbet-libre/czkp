//! Voucher accounting: limit, success proof, weights and the obligation addresses.
mod common;
use czkp::standing::{Policy, Q, State};
use czkp::voucher::{self, ADMIN, Account, MEMBER, PUNISHED, REWARD, ROOT, SUCCESS};

fn policy() -> Policy {
    Policy::derive(common::reference()).unwrap()
}

fn domain() -> [u8; 32] {
    let mut d = [0u8; 32];
    let tag = b"cfrm.account-state.v2";
    d[32 - tag.len()..].copy_from_slice(tag);
    d
}

#[test]
fn newcomers_have_no_allowance_until_their_own_success() {
    let p = policy();
    let mut a = Account::default();
    assert_eq!(voucher::limit(&p, MEMBER, &a, 40).unwrap(), 0);
    a.proven = 20_000;
    // slope 1/10: cap 40 gives 4, clamped to the member maximum of 3.
    assert_eq!(voucher::limit(&p, MEMBER, &a, 40).unwrap(), 3);
    assert_eq!(voucher::limit(&p, MEMBER, &a, 3).unwrap(), 1);
    assert_eq!(voucher::limit(&p, MEMBER, &a, 1).unwrap(), 1);
}

#[test]
fn roles_clamp_independently_and_unknown_roles_refuse() {
    let p = policy();
    let a = Account::default();
    assert_eq!(voucher::limit(&p, ADMIN, &a, 3).unwrap(), 50);
    assert_eq!(voucher::limit(&p, ADMIN, &a, 41).unwrap(), 82);
    assert_eq!(voucher::limit(&p, ADMIN, &a, 200).unwrap(), 100);
    assert_eq!(voucher::limit(&p, ROOT, &a, 3).unwrap(), 500);
    assert!(voucher::limit(&p, 3, &a, 3).is_err());
}

#[test]
fn bonus_adds_and_lost_subtracts_without_underflow() {
    let p = policy();
    let a = Account {
        proven: 1,
        bonus: 2,
        lost: 1,
        ..Account::default()
    };
    assert_eq!(voucher::limit(&p, MEMBER, &a, 40).unwrap(), 4);
    let b = Account {
        proven: 1,
        lost: 9,
        ..Account::default()
    };
    assert_eq!(voucher::limit(&p, MEMBER, &b, 40).unwrap(), 0);
}

#[test]
fn admission_spends_one_voucher_and_overshoot_is_lost_for_good() {
    let p = policy();
    let mut a = Account {
        proven: 1,
        ..Account::default()
    };
    let first = a.admit(&p, MEMBER, 40).unwrap();
    assert_eq!((a.away, a.lost), (1, 0));
    assert_eq!(first.limit, 3);
    a.admit(&p, MEMBER, 40).unwrap();
    a.admit(&p, MEMBER, 40).unwrap();
    assert_eq!(voucher::remaining(&p, MEMBER, &a, 40).unwrap(), 0);
    let over = a.admit(&p, MEMBER, 40).unwrap();
    assert!(over.overshoot);
    assert_eq!((a.away, a.lost), (3, 1));
    // The lost voucher lowers the limit for good; success on it returns nothing.
    assert_eq!(voucher::limit(&p, MEMBER, &a, 40).unwrap(), 2);
    let mut entry = over;
    a.consume_success(&mut entry).unwrap();
    assert_eq!(a.away, 3);
    assert!(a.consume_success(&mut entry).is_err());
}

#[test]
fn success_returns_the_voucher_once() {
    let p = policy();
    let mut a = Account {
        proven: 1,
        ..Account::default()
    };
    let mut entry = a.admit(&p, MEMBER, 40).unwrap();
    a.consume_success(&mut entry).unwrap();
    assert_eq!((a.away, a.returned), (0, 1));
    assert!(a.consume_success(&mut entry).is_err());
}

#[test]
fn punishment_weight_is_one_over_the_limit_at_issuance_and_decays_like_v5() {
    let p = policy();
    assert_eq!(voucher::punish_weight(1), Q);
    assert_eq!(voucher::punish_weight(3), Q.div_ceil(3));
    assert_eq!(voucher::punish_weight(0), Q);
    let a = Account {
        proven: 1,
        ..Account::default()
    };
    let mut entry = voucher::Entry {
        limit: 4,
        done: false,
        overshoot: false,
        punished_seen: 0,
        rewards_seen: 0,
    };
    let mut s = State::new(0, 0);
    a.consume_punished(&mut entry, &mut s).unwrap();
    assert_eq!((s.pr, entry.punished_seen), (Q / 4, 1));
    let before = s.pr;
    s.answer_given(&p);
    assert!(s.pr < before && s.pr > 0);
}

#[test]
fn reward_is_capped_and_never_lowers_a_larger_bonus() {
    let p = policy();
    assert_eq!(voucher::rewarded(&p, 0), 1);
    assert_eq!(voucher::rewarded(&p, 1), 2);
    assert_eq!(voucher::rewarded(&p, 2), 2);
    assert_eq!(voucher::rewarded(&p, 5), 5);
    let mut off = common::reference();
    off.voucher.reward_cap = 0;
    assert_eq!(voucher::rewarded(&Policy::derive(off).unwrap(), 0), 0);
}

#[test]
fn success_needs_every_condition() {
    let p = policy();
    let mut s = State::new(100, 2 * Q);
    s.day = 130;
    let mut a = Account {
        answers: 3,
        ..Account::default()
    };
    assert!(voucher::success_ready(&p, &s, &a, 1));
    assert!(!voucher::success_ready(&p, &s, &a, 2), "two punishments");
    a.answers = 2;
    assert!(!voucher::success_ready(&p, &s, &a, 0), "too few partners");
    a.answers = 3;
    s.day = 129;
    assert!(!voucher::success_ready(&p, &s, &a, 0), "too early");
    s.day = 130;
    a.proven = 1;
    assert!(!voucher::success_ready(&p, &s, &a, 0), "only once");
    a.proven = 0;
    for _ in 0..50 {
        s.punished(false);
    }
    assert!(voucher::braked(&p, s.cap(&p)));
    assert!(!voucher::success_ready(&p, &s, &a, 0), "braked");
}

#[test]
fn addresses_are_domain_separated_and_deterministic() {
    let d = domain();
    let bond = [7u8; 32];
    let other = [8u8; 32];
    let tags = [
        voucher::obligation_tag(&d, &bond, SUCCESS, 0).unwrap(),
        voucher::obligation_tag(&d, &bond, PUNISHED, 1).unwrap(),
        voucher::obligation_tag(&d, &bond, PUNISHED, 2).unwrap(),
        voucher::obligation_tag(&d, &bond, REWARD, 1).unwrap(),
        voucher::obligation_tag(&d, &other, SUCCESS, 0).unwrap(),
        voucher::bond_commit(&d, &bond).unwrap(),
        voucher::bond_key(&d, &bond).unwrap(),
    ];
    for i in 0..tags.len() {
        for j in i + 1..tags.len() {
            assert_ne!(tags[i], tags[j], "{i} {j}");
        }
    }
    assert_eq!(
        tags[0],
        voucher::obligation_tag(&d, &bond, SUCCESS, 0).unwrap()
    );
    let m = voucher::member_tag(&d, &[1; 32], &[2; 32]).unwrap();
    assert_ne!(m, voucher::member_tag(&d, &[1; 32], &[3; 32]).unwrap());
}

#[test]
fn parameters_validate_and_change_the_digest() {
    let mut p = common::reference();
    p.voucher.days = 13;
    assert!(Policy::derive(p).is_err(), "below the platform floor");
    p = common::reference();
    p.voucher.min[0] = 4;
    assert!(Policy::derive(p).is_err(), "min above max");
    p = common::reference();
    p.voucher.brake_cap = 0;
    assert!(Policy::derive(p).is_err());
    let base = Policy::derive(common::reference())
        .unwrap()
        .digest(&domain())
        .unwrap();
    let mut changed = common::reference();
    changed.voucher.k = 4;
    let moved = Policy::derive(changed).unwrap().digest(&domain()).unwrap();
    assert_ne!(base, moved);
}

fn hex(b: &[u8; 32]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// Vectors shared with the Noir probe (cblc tests/voucher-probe.mts, same file).
/// Regenerate with `UPDATE_VECTORS=1 cargo test --test voucher golden`.
#[test]
fn golden_vectors_are_current() {
    let p = policy();
    let d = domain();
    let mut cases = Vec::new();
    let bonds = [[7u8; 32], [0xa5u8; 32]];
    let mut i = 0usize;
    for role in [MEMBER, ADMIN, ROOT] {
        for cap in [1u64, 3, 8, 24, 41, 80, 400] {
            for (proven, away, lost, bonus) in [
                (0u64, 0u64, 0u64, 0u64),
                (5, 0, 0, 0),
                (5, 2, 0, 1),
                (5, 3, 1, 2),
                (5, 60, 0, 0),
            ] {
                let a = Account {
                    proven,
                    away,
                    lost,
                    bonus,
                    ..Account::default()
                };
                let bond = bonds[i % 2];
                let kind = [SUCCESS, PUNISHED, REWARD][i % 3];
                let n = (i % 5) as u64;
                let weight_limit = (i % 7) as u64;
                i += 1;
                let mut spent = a;
                let entry = spent.admit(&p, role, cap).unwrap();
                cases.push(serde_json::json!({
                    "role": role, "cap": cap,
                    "account": {"proven": proven, "away": away, "lost": lost, "bonus": bonus},
                    "bond": hex(&bond), "kind": kind, "n": n, "weight_limit": weight_limit,
                    "community": hex(&[1; 32]), "member": hex(&[2; 32]),
                    "expect": {
                        "limit": voucher::limit(&p, role, &a, cap).unwrap(),
                        "remaining": voucher::remaining(&p, role, &a, cap).unwrap(),
                        "weight": voucher::punish_weight(weight_limit),
                        "rewarded": voucher::rewarded(&p, bonus),
                        "away": spent.away, "lost": spent.lost,
                        "entry_limit": entry.limit, "overshoot": u64::from(entry.overshoot),
                        "tag": hex(&voucher::obligation_tag(&d, &bond, kind, n).unwrap()),
                        "commit": hex(&voucher::bond_commit(&d, &bond).unwrap()),
                        "key": hex(&voucher::bond_key(&d, &bond).unwrap()),
                        "entry": hex(&entry.digest(&d).unwrap()),
                        "member_tag": hex(&voucher::member_tag(&d, &[1; 32], &[2; 32]).unwrap()),
                    }
                }));
            }
        }
    }
    let text = serde_json::to_string_pretty(&serde_json::json!({ "cases": cases })).unwrap() + "\n";
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/voucher/golden.json"
    );
    if std::env::var_os("UPDATE_VECTORS").is_some() {
        std::fs::write(path, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
}
