//! `Params::from_rulebook`: the only way parameters come to exist.
use crate::common;
use crate::common::catalogue;
use czkp::standing::{Params, RULEBOOK_KEYS, Setting};

#[test]
fn the_reference_community_reads_every_key_and_nothing_else() {
    let asked = std::cell::RefCell::new(Vec::new());
    Params::from_rulebook(|key| {
        asked.borrow_mut().push(key.to_owned());
        catalogue(key)
    })
    .unwrap();
    let mut asked = asked.into_inner();
    asked.sort();
    asked.dedup();
    let mut expected: Vec<String> = RULEBOOK_KEYS.iter().map(|key| (*key).to_owned()).collect();
    expected.sort();
    assert_eq!(asked, expected);
    for key in RULEBOOK_KEYS {
        assert!(catalogue(key).is_some(), "{key}");
    }
}

#[test]
fn the_catalogue_slopes_become_q16_rounded_to_nearest() {
    let params = common::reference();
    assert_eq!(params.voucher.slope_q, [6_554, 131_072, 1_638_400]);
    assert_eq!(params.voucher.min, [1, 50, 500]);
    assert_eq!(params.voucher.max, [3, 100, 1000]);
    assert_eq!(params.voucher.reward_cap, 2);
}

#[test]
fn a_missing_key_is_an_error_never_a_default() {
    for missing in RULEBOOK_KEYS {
        assert!(
            Params::from_rulebook(|key| if key == missing { None } else { catalogue(key) })
                .is_err(),
            "{missing}"
        );
    }
}

#[test]
fn the_reward_switch_zeroes_the_cap_and_a_wrong_type_or_range_is_refused() {
    let off = Params::from_rulebook(|key| match key {
        "voucher.reward.enabled" => Some(Setting::Flag(false)),
        _ => catalogue(key),
    })
    .unwrap();
    assert_eq!(off.voucher.reward_cap, 0);
    let wrong_type = |key: &str, value: Setting| {
        Params::from_rulebook(|asked| {
            if asked == key {
                Some(value)
            } else {
                catalogue(asked)
            }
        })
    };
    assert!(wrong_type("voucher.reward.enabled", Setting::Integer(1)).is_err());
    assert!(wrong_type("standing.c0", Setting::Number(3.5)).is_err());
    assert!(wrong_type("standing.c0", Setting::Number(-1.0)).is_err());
    // Outside the safe ranges.
    assert!(wrong_type("standing.c0", Setting::Integer(17)).is_err());
    assert!(wrong_type("voucher.brake_cap", Setting::Integer(5)).is_err());
    assert!(wrong_type("voucher.min.member", Setting::Integer(4)).is_err());
    assert!(wrong_type("voucher.slope.root", Setting::Number(65.0)).is_err());
    // A whole number is accepted wherever a decimal is, and a whole decimal as a count.
    assert!(wrong_type("voucher.slope.admin", Setting::Integer(2)).is_ok());
    assert!(wrong_type("standing.c0", Setting::Number(3.0)).is_ok());
}

#[test]
fn another_value_is_another_digest() {
    let domain = [7u8; 32];
    let digest = |params: Params| {
        czkp::standing::Policy::derive(params)
            .unwrap()
            .digest(&domain)
            .unwrap()
    };
    let changed = Params::from_rulebook(|key| match key {
        "voucher.slope.member" => Some(Setting::Number(0.2)),
        _ => catalogue(key),
    })
    .unwrap();
    assert_ne!(digest(common::reference()), digest(changed));
    assert_eq!(digest(common::reference()), digest(common::reference()));
}

#[test]
fn the_policy_digest_is_the_one_the_circuit_pins() {
    let digest = common::reference().policy_digest().unwrap();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "13869f92e82373e15e5b9bbaf09bb0d2f4a71e7af912d20c68ae8ceb98710231"
    );
}

#[test]
fn the_activation_owner_binds_the_address_and_the_one_time_token_message() {
    let owner = czkp::activation_owner("gardenclub", &[1; 32]);
    assert_eq!(owner, czkp::activation_owner("gardenclub", &[1; 32]));
    assert_ne!(owner, czkp::activation_owner("gardenclub", &[2; 32]));
    assert_ne!(owner, czkp::activation_owner("gardenclu", &[1; 32]));
    // Length-prefixed: shifting bytes between the two inputs changes the result.
    assert_ne!(
        czkp::activation_owner("ab", b"c"),
        czkp::activation_owner("a", b"bc")
    );
}
/// Negative and NaN decimals are refused as Q16 slopes: without the range guard
/// the saturating float cast would admit them as a zero slope.
#[test]
fn negative_or_nan_decimals_are_not_q16_slopes() {
    let slope = |value: f64| {
        Params::from_rulebook(|key| {
            if key == "voucher.slope.admin" {
                Some(Setting::Number(value))
            } else {
                catalogue(key)
            }
        })
    };
    assert!(slope(-1.0).is_err());
    assert!(slope(f64::NAN).is_err());
}
