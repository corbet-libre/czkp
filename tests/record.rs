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

const PERIOD: u64 = 86_400;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn maintained_presentation_signature_refuses_substitution_and_expiry() {
    use czkp::record::{Context, Presentation, Record, Use, presentation_key_commitment};
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[7; 32]);
    let context = Context {
        purpose: Use::ForumListing,
        challenge: [8; 32],
        expires_at: 173000,
    };
    let record = Record {
        epoch: epoch(),
        owner: [9; 32],
        presentation_key_commitment: presentation_key_commitment(&key.verifying_key().to_bytes()),
        shares: None,
    };
    let presentation = Presentation {
        signature: key
            .sign(&record.presentation_bytes(&context).unwrap())
            .to_bytes()
            .to_vec(),
        public_key: key.verifying_key().to_bytes(),
        record: record.clone(),
        context: context.clone(),
        proof: "aabb".into(),
    };
    // Binding only, deliberately NOT proof acceptance. Real proofs are exercised
    // by the original issuer fixture in the relation's owning repository.
    presentation
        .check_binding(&context, &epoch(), &[9; 32], 172900)
        .unwrap();
    for case in 0..12 {
        let mut bad = presentation.clone();
        match case {
            0 => bad.context.challenge[0] ^= 1,
            1 => bad.context.purpose = Use::FirstContact,
            2 => bad.context.expires_at += 1,
            3 => bad.record.epoch.epoch += 1,
            4 => bad.record.epoch.root[0] ^= 1,
            5 => bad.record.owner[0] ^= 1,
            6 => bad.record.shares = Some([0, 0, 10000]),
            7 => bad.public_key[0] ^= 1,
            8 => bad.signature[0] ^= 1,
            9 => bad.proof.clear(),
            10 => bad.record.presentation_key_commitment[0] ^= 1,
            _ => bad.record.epoch.download_digest[0] ^= 1,
        }
        assert!(
            bad.check_binding(&context, &epoch(), &[9; 32], 172900)
                .is_err()
        );
    }
    assert!(
        presentation
            .check_binding(&context, &epoch(), &[9; 32], 173000)
            .is_err()
    );
    assert!(
        presentation
            .check_binding(&context, &epoch(), &[9; 32], 172799)
            .is_err()
    );
    assert!(
        presentation
            .check_binding(&context, &next_epoch(), &[9; 32], 259200)
            .is_err()
    );
}

fn next_epoch() -> Epoch {
    let mut v = epoch();
    v.epoch = 3;
    v.starts_at = 259_200;
    v.expires_at = 345_600;
    v
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn successor_fencing_and_policy_binding() {
    let good = epoch();
    good.check_successor(&good, PERIOD).unwrap();
    let mut higher = next_epoch();
    higher.check_successor(&good, PERIOD).unwrap();
    // Higher epoch may rotate independently-authorized material.
    higher.root = [9; 32];
    higher.download_digest = [8; 32];
    higher.proof_scope.circuit_digest = [7; 32];
    higher.leaf_count = 8192;
    higher.check_successor(&good, PERIOD).unwrap();
    assert_eq!(good.check_successor(&higher, PERIOD), Err(Error::Replay));
    let mut rolled_policy = next_epoch();
    rolled_policy.policy_epoch = 6;
    assert_eq!(
        rolled_policy.check_successor(&good, PERIOD),
        Err(Error::Replay)
    );
    let mut same_rolled = good.clone();
    same_rolled.policy_epoch = 6;
    assert_eq!(
        same_rolled.check_successor(&good, PERIOD),
        Err(Error::Replay)
    );
    for case in 0..7 {
        let mut bad = good.clone();
        match case {
            0 => bad.policy_epoch = 8,
            1 => bad.root = [9; 32],
            2 => bad.proof_scope.circuit_digest = [9; 32],
            3 => bad.proof_scope.verifying_key_digest = [9; 32],
            4 => bad.leaf_count = 8192,
            5 => bad.download_digest = [9; 32],
            6 => bad.download_bytes = 4097,
            _ => unreachable!(),
        }
        assert_eq!(
            bad.check_successor(&good, PERIOD),
            Err(Error::PolicyMismatch)
        );
    }
    for case in 0..10 {
        let mut bad = good.clone();
        match case {
            0 => bad.community[0] ^= 1,
            1 => bad.starts_at += 1,
            2 => bad.expires_at += 1,
            3 => bad.root = [0; 32],
            4 => bad.proof_scope.circuit_digest = [0; 32],
            5 => bad.proof_scope.verifying_key_digest = [0; 32],
            6 => bad.leaf_count = 0,
            7 => bad.download_digest = [0; 32],
            8 => bad.download_bytes = 0,
            9 => bad.download_bytes = MAX_DOWNLOAD_BYTES + 1,
            _ => unreachable!(),
        }
        assert_eq!(bad.check_successor(&good, PERIOD), Err(Error::InvalidInput));
        assert_eq!(good.check_successor(&bad, PERIOD), Err(Error::InvalidInput));
    }
    let mut forked = good.clone();
    forked.community = [2; 32];
    assert_eq!(
        forked.check_successor(&good, PERIOD),
        Err(Error::InvalidInput)
    );
    assert_eq!(good.check_successor(&good, 3600), Err(Error::InvalidInput));
    assert_eq!(good.check_successor(&good, 0), Err(Error::InvalidInput));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn object_digest_and_length_binding() {
    let mut v = epoch();
    v.download_bytes = 3;
    v.download_digest = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    v.check_object(b"abc").unwrap();
    for bytes in [
        b"ab".as_slice(),
        b"abcd".as_slice(),
        b"abd".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(v.check_object(bytes), Err(Error::InvalidInput));
    }
    for declared in [0, MAX_DOWNLOAD_BYTES + 1] {
        let mut over = epoch();
        over.download_bytes = declared;
        assert_eq!(over.check_object(b"abc"), Err(Error::InvalidInput));
    }
}
