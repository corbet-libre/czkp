//! Canonical record-epoch descriptor, blinded leaf transcript and bound checks.

use czkp::record::{Epoch, Leaf, MAX_DOWNLOAD_BYTES, Purpose};
use czkp::{Error, MAX_INTEGER};

fn epoch() -> Epoch {
    Epoch {
        purpose: Purpose::RecordEpochV1,
        community: [1; 32],
        policy_epoch: 7,
        epoch: 2,
        starts_at: 172800,
        expires_at: 259200,
        root: [2; 32],
        proof_scope: czkp::ProofScope {
            circuit_digest: [4; 32],
            verifying_key_digest: [5; 32],
        },
        leaf_count: 5000,
        download_digest: [3; 32],
        download_bytes: 4096,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn configured_epoch_and_transport_refusals() {
    let good = epoch();
    good.validate(&[1; 32], 86400).unwrap();
    assert_eq!(good.depth(), 13);
    assert_eq!(good.check_time(172799), Err(Error::ClockRollback));
    good.check_time(172800).unwrap();
    good.check_time(259199).unwrap();
    assert_eq!(good.check_time(259200), Err(Error::Expired));
    for case in 0..15 {
        let mut bad = good.clone();
        match case {
            0 => bad.community[0] ^= 1,
            1 => bad.policy_epoch = MAX_INTEGER + 1,
            2 => bad.epoch = 0,
            3 => bad.epoch = MAX_INTEGER + 1,
            4 => bad.starts_at = MAX_INTEGER + 1,
            5 => bad.expires_at = MAX_INTEGER + 1,
            6 => bad.starts_at += 1,
            7 => bad.expires_at += 1,
            8 => bad.root = [0; 32],
            9 => bad.leaf_count = 0,
            10 => bad.download_digest = [0; 32],
            11 => bad.download_bytes = 0,
            12 => bad.download_bytes = MAX_DOWNLOAD_BYTES + 1,
            13 => bad.proof_scope.circuit_digest = [0; 32],
            14 => bad.proof_scope.verifying_key_digest = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(bad.validate(&[1; 32], 86400), Err(Error::InvalidInput));
    }
    for period in [0, 3600, MAX_INTEGER + 1, MAX_INTEGER] {
        assert_eq!(good.validate(&[1; 32], period), Err(Error::InvalidInput));
    }
    for (count, depth) in [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3), (u32::MAX, 32)] {
        let mut value = good.clone();
        value.leaf_count = count;
        assert_eq!(value.depth(), depth);
    }
    let mut wire = serde_json::to_value(&good).unwrap();
    assert_eq!(serde_json::from_value::<Epoch>(wire.clone()).unwrap(), good);
    wire["member"] = serde_json::json!("no member labels in public descriptor");
    assert!(serde_json::from_value::<Epoch>(wire).is_err());
    let mut wire = serde_json::to_value(good).unwrap();
    wire["purpose"] = serde_json::json!("cblc.record-epoch.v0");
    assert!(serde_json::from_value::<Epoch>(wire).is_err());
}

fn leaf() -> Leaf {
    let mut state = [0; 32];
    state[31] = 5;
    Leaf {
        owner: [3; 32],
        version: 4,
        state,
        required_inbox: [6; 32],
        blinding: [7; 32],
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_leaf_transcript_and_epoch_blinding() {
    let expected = [
        0x3e, 0x82, 0x79, 0x2a, 0x73, 0x83, 0x29, 0x9a, 0x04, 0x51, 0x7c, 0x02, 0x07, 0xc1, 0xbc,
        0xac, 0xda, 0xbd, 0x4a, 0x36, 0x1f, 0xe6, 0x11, 0xc8, 0x0f, 0xb5, 0xbb, 0x0c, 0xa9, 0x37,
        0x02, 0x3f,
    ];
    assert_eq!(leaf().commitment(&[1; 32], 2).unwrap(), expected);
    for case in 0..5 {
        let mut changed = leaf();
        match case {
            0 => changed.owner[0] ^= 1,
            1 => changed.version += 1,
            2 => changed.state[31] += 1,
            3 => changed.required_inbox[0] ^= 1,
            4 => changed.blinding[0] ^= 1,
            _ => unreachable!(),
        }
        assert_ne!(changed.commitment(&[1; 32], 2).unwrap(), expected);
    }
    assert_ne!(leaf().commitment(&[2; 32], 2).unwrap(), expected);
    assert_ne!(leaf().commitment(&[1; 32], 3).unwrap(), expected);
    for bad_epoch in [0, MAX_INTEGER + 1] {
        assert_eq!(
            leaf().commitment(&[1; 32], bad_epoch),
            Err(Error::InvalidInput)
        );
    }
    for case in 0..4 {
        let mut bad = leaf();
        match case {
            0 => bad.version = MAX_INTEGER + 1,
            1 => bad.blinding = [0; 32],
            2 => bad.state = [0; 32],
            3 => bad.state = [0xff; 32],
            _ => unreachable!(),
        }
        assert_eq!(bad.commitment(&[1; 32], 2), Err(Error::InvalidInput));
    }
}
