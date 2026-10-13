//! The settings catalogue's values for the standing and voucher parameters, as the
//! tests' reference community. czkp itself has no defaults: these mirror the
//! catalogue (crbk `platform_catalog`), and the rulebook crate's own test pins the
//! same digest so the two cannot drift apart.
#![allow(dead_code)]
use czkp::standing::{Params, Setting};

pub fn catalogue(key: &str) -> Option<Setting> {
    use Setting::{Flag, Integer, Number};
    Some(match key {
        "standing.c0" => Integer(3),
        "standing.h_a" => Integer(14),
        "standing.h_g" => Integer(14),
        "standing.n_half" => Integer(25),
        "standing.n_c" => Integer(60),
        "standing.e_q" => Integer(16_384),
        "standing.r_max" => Integer(40),
        "standing.r_age" => Integer(2),
        "standing.c_max_q" => Integer(52_428),
        "standing.c_vet" => Integer(30),
        "standing.age_vet" => Integer(60),
        "standing.boost_q" => Integer(65_536),
        "standing.boost_days" => Integer(30),
        "standing.slope_q" => Integer(262_144),
        "standing.mid_q" => Integer(49_152),
        "standing.kappa_q" => Integer(131_072),
        "standing.loan_use_q" => Integer(16_384),
        "voucher.slope.member" => Number(0.1),
        "voucher.slope.admin" => Number(2.0),
        "voucher.slope.root" => Number(25.0),
        "voucher.min.member" => Integer(1),
        "voucher.min.admin" => Integer(50),
        "voucher.min.root" => Integer(500),
        "voucher.max.member" => Integer(3),
        "voucher.max.admin" => Integer(100),
        "voucher.max.root" => Integer(1000),
        "voucher.success.min_days" => Integer(30),
        "voucher.success.min_conversations" => Integer(3),
        "voucher.success.max_punishments" => Integer(1),
        "voucher.brake_cap" => Integer(1),
        "voucher.reward.enabled" => Flag(true),
        "voucher.reward.cap" => Integer(2),
        _ => return None,
    })
}

/// The reference community's parameters.
pub fn reference() -> Params {
    Params::from_rulebook(catalogue).unwrap()
}
