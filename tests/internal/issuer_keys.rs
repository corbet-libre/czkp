//! Issuer key ring: rotation keeps retired keys, certificates verify only inside the
//! period of their key, and publication refuses malformed rings.
use super::*;
use crate::certificate::AcceptedState;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn public(secret: u8) -> [u8; 64] {
    SigningKey::from_slice(&[secret; 32])
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()[1..]
        .try_into()
        .unwrap()
}

fn sign(secret: u8, bytes: &[u8]) -> [u8; 64] {
    let signature: Signature = SigningKey::from_slice(&[secret; 32]).unwrap().sign(bytes);
    signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into()
}

fn state(community: u8, accepted_at: u64) -> AcceptedState {
    AcceptedState {
        community: [community; 32],
        identity: [community ^ 0x80; 32],
        owner: [2; 32],
        state: [3; 32],
        scope: [4; 32],
        version: 7,
        accepted_at,
    }
}

fn period(key: u8, from: u64, until: Option<u64>) -> CertificateKeyPeriod {
    CertificateKeyPeriod {
        public_key: public(key).to_vec(),
        valid_from: from,
        valid_until: until,
    }
}

#[test]
fn rotation_retires_the_open_key_and_keeps_every_retired_key() {
    let one = advance(&[], &public(3), 100).unwrap().unwrap();
    assert_eq!(one, vec![period(3, 100, None)]);
    assert_eq!(advance(&one, &public(3), 500).unwrap(), None);
    let two = advance(&one, &public(4), 500).unwrap().unwrap();
    assert_eq!(two, vec![period(3, 100, Some(500)), period(4, 500, None)]);
    // Rotating within the first second still leaves disjoint periods.
    let quick = advance(&one, &public(4), 100).unwrap().unwrap();
    assert_eq!(quick, vec![period(3, 100, Some(101)), period(4, 101, None)]);
    validate(&quick).unwrap();
    // Back to an old key opens a NEW period; the retired one keeps its own.
    let three = advance(&two, &public(3), 900).unwrap().unwrap();
    assert_eq!(three.len(), 3);
    assert_eq!(three[2], period(3, 900, None));
    assert_eq!(key_at(&three, 200).unwrap(), public(3));
    assert_eq!(key_at(&three, 600).unwrap(), public(4));
    assert_eq!(key_at(&three, 950).unwrap(), public(3));
    assert_eq!(key_at(&three, 99), Err(Error::PolicyMismatch));
}

#[test]
fn an_old_certificate_verifies_in_its_period_and_a_retired_key_fails_outside_it() {
    let ring = advance(
        &advance(&[], &public(3), 100).unwrap().unwrap(),
        &public(4),
        500,
    )
    .unwrap()
    .unwrap();
    // Made before the rotation, verified after it.
    let old = state(1, 200);
    verify_accepted(&ring, &old, &sign(3, &old.bytes())).unwrap();
    let new = state(1, 700);
    verify_accepted(&ring, &new, &sign(4, &new.bytes())).unwrap();
    // The retired key signing after its period: refused.
    let late = state(1, 700);
    assert!(verify_accepted(&ring, &late, &sign(3, &late.bytes())).is_err());
    // The new key cannot sign into the old period either.
    let early = state(1, 200);
    assert!(verify_accepted(&ring, &early, &sign(4, &early.bytes())).is_err());
    // Before the first period there is no key at all.
    let before = state(1, 50);
    assert!(verify_accepted(&ring, &before, &sign(3, &before.bytes())).is_err());
    // Exact periods for anonymous deposits.
    assert_eq!(
        period(3, 100, Some(500)),
        super::period(&ring, &public(3), 100).unwrap()
    );
    assert!(super::period(&ring, &public(3), 500).is_err());
    assert!(super::period(&ring, &public(5), 100).is_err());
}

#[test]
fn a_certificate_for_one_community_fails_for_another() {
    let ring = advance(&[], &public(3), 100).unwrap().unwrap();
    let x = state(1, 200);
    let signature = sign(3, &x.bytes());
    verify_accepted(&ring, &x, &signature).unwrap();
    let mut y = x;
    y.community = [2; 32];
    assert!(verify_accepted(&ring, &y, &signature).is_err());
    // Same address hash, another incarnation (identity): refused as well.
    let mut reused = x;
    reused.identity[0] ^= 1;
    assert!(verify_accepted(&ring, &reused, &signature).is_err());
}

#[test]
fn malformed_rings_are_refused() {
    let max = (1 << 53) - 1;
    assert!(validate(&[]).is_err());
    let good = vec![period(3, 100, Some(500)), period(4, 500, None)];
    validate(&good).unwrap();
    for case in 0..7 {
        let mut ring = good.clone();
        match case {
            0 => ring[0].valid_until = None,
            1 => ring[1].valid_from = 499,
            2 => ring[0].valid_until = Some(100),
            3 => ring[0].valid_from = 0,
            4 => ring[1].valid_until = Some(max + 1),
            5 => ring[0].public_key = vec![4; 63],
            _ => ring[0].public_key = vec![0; 64],
        }
        assert!(validate(&ring).is_err(), "case {case}");
    }
    let full: Vec<_> = (0..MAX_PERIODS as u64)
        .map(|i| period(3, 1 + 2 * i, Some(2 + 2 * i)))
        .collect();
    validate(&full).unwrap();
    assert_eq!(advance(&full, &public(4), 10_000), Err(Error::Capacity));
    assert!(advance(&good, &public(3), 0).is_err());
}

#[test]
fn the_ring_travels_as_camel_case_json() {
    let ring = vec![period(3, 100, Some(500)), period(4, 500, None)];
    let text = serde_json::to_string(&ring).unwrap();
    assert!(text.contains("\"validFrom\":500") && !text.contains("validUntil\":null"));
    let back: Vec<CertificateKeyPeriod> = serde_json::from_str(&text).unwrap();
    assert_eq!(back, ring);
}
#[test]
fn the_exclusive_end_of_a_period_holds_no_key() {
    let ring = advance(&[], &public(3), 100).unwrap().unwrap();
    assert_eq!(key_at(&ring, 100).unwrap(), public(3));
    // The open period ends at the largest circuit integer, exclusively.
    assert_eq!(key_at(&ring, (1 << 53) - 1), Err(Error::PolicyMismatch));
}

#[test]
fn an_inverted_period_is_refused() {
    let ring = vec![CertificateKeyPeriod {
        public_key: public(3).to_vec(),
        valid_from: 500,
        valid_until: Some(100),
    }];
    assert_eq!(validate(&ring), Err(Error::InvalidInput));
}

use crate::certificate::EpochAncestry;

fn ancestry_fixture(issued_at: u64) -> EpochAncestry {
    EpochAncestry {
        community: [1; 32],
        owner: [2; 32],
        epoch: 3,
        root: [4; 32],
        frozen_leaf: [5; 32],
        state: [6; 32],
        version: 7,
        circuit_digest: [8; 32],
        verifying_key_digest: [9; 32],
        issued_at,
    }
}

#[test]
fn ancestry_verifies_only_with_the_key_of_its_own_issuance_time() {
    let ring = advance(&[], &public(3), 100).unwrap().unwrap();
    let body = ancestry_fixture(200);
    let signature = sign(3, &body.bytes().unwrap());
    verify_ancestry(&ring, &body, &signature).unwrap();
    // The wrong key's signature over the same bytes is refused.
    let forged = sign(4, &body.bytes().unwrap());
    assert_eq!(
        verify_ancestry(&ring, &body, &forged),
        Err(Error::Signature)
    );
}
