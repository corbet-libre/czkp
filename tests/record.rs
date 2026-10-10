//! Original public record descriptor, issuer signatures and presentation binding.

use czkp::record::{Epoch, Leaf, MAX_DOWNLOAD_BYTES, Purpose};
use czkp::{Error, MAX_INTEGER};

fn epoch() -> Epoch {
    Epoch {
        purpose: Purpose::RecordEpochV3,
        community: [1; 32],
        policy_epoch: 7,
        epoch: 2,
        starts_at: 172800,
        expires_at: 259200,
        root: [2; 32],
        issuer_key: ed25519_dalek::SigningKey::from_bytes(&[19; 32])
            .verifying_key()
            .to_bytes(),
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
    for case in 0..17 {
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
            15 => bad.leaf_count = (1 << 20) + 1,
            16 => bad.issuer_key = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(bad.validate(&[1; 32], 86400), Err(Error::InvalidInput));
    }
    for period in [0, 3600, MAX_INTEGER + 1, MAX_INTEGER] {
        assert_eq!(good.validate(&[1; 32], period), Err(Error::InvalidInput));
    }
    for (count, depth) in [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3), (1 << 20, 20)] {
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
    // Library-level domain/injectivity refusals only. Actual frozen issuer and
    // Noir/BB proof interoperability require their separate qualification.
    let expected = leaf().commitment(&[1; 32], 2).unwrap();
    czkp::field(&expected, true).unwrap();
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn maintained_epoch_tree_verifies_padded_paths_and_refuses_substitution() {
    use czkp::record::EpochTree;
    use rs_merkle::MerkleTree;
    let mut leaves = (0..3)
        .map(|index| {
            let mut value = leaf();
            value.owner = [3 + index; 32];
            value.commitment(&[1; 32], 2).unwrap()
        })
        .collect::<Vec<_>>();
    // The original common-object builder pads to a power of two, at least two.
    leaves.push([0; 32]);
    let tree = MerkleTree::<EpochTree>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    czkp::field(&root, true).unwrap();
    let proof = tree.proof(&[2]);
    assert_eq!(proof.proof_hashes().len(), 2);
    assert!(proof.verify(root, &[2], &[leaves[2]], 4));
    assert!(!proof.verify(root, &[0], &[leaves[2]], 4));
    assert!(!proof.verify(root, &[2], &[leaves[1]], 4));
    let mut changed_root = root;
    changed_root[31] ^= 1;
    assert!(!proof.verify(changed_root, &[2], &[leaves[2]], 4));
    assert_eq!(
        czkp::poseidon::hash(&[[0xff; 32]]),
        Err(Error::InvalidInput)
    );
    // Inclusion in a locally built tree is not authenticated epoch authority.
}

const PERIOD: u64 = 86_400;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn maintained_presentation_signature_refuses_substitution_and_expiry() {
    use czkp::record::{Context, Presentation, Record, Use, presentation_key};
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
        presentation_key: presentation_key(&key.verifying_key().to_bytes()),
        blinded_leaf: [1; 32],
        certificate: ed25519_dalek::Signer::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[19; 32]),
            &czkp::record::certificate_bytes(&[1; 32], 2, &[1; 32]).unwrap(),
        )
        .to_bytes()
        .to_vec(),
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
    for case in 0..15 {
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
            10 => bad.record.presentation_key[0] ^= 1,
            11 => bad.record.epoch.download_digest[0] ^= 1,
            12 => bad.record.epoch.issuer_key[0] ^= 1,
            13 => bad.record.blinded_leaf[0] ^= 1,
            _ => bad.record.certificate[0] ^= 1,
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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn issuer_certificates_require_the_original_key_scope_and_canonical_leaf() {
    use czkp::record::{certificate_bytes, verify_certificate};
    use ed25519_dalek::{Signer, SigningKey};
    let issuer = SigningKey::from_bytes(&[19; 32]);
    let key = issuer.verifying_key().to_bytes();
    let leaf = [1; 32];
    let signature = issuer
        .sign(&certificate_bytes(&[1; 32], 2, &leaf).unwrap())
        .to_bytes();
    verify_certificate(&key, &[1; 32], 2, &leaf, &signature).unwrap();

    let other_issuer = SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes();
    for (issuer, community, epoch, leaf) in [
        (other_issuer, [1; 32], 2, leaf),
        (key, [2; 32], 2, leaf),
        (key, [1; 32], 3, leaf),
        (key, [1; 32], 2, [2; 32]),
    ] {
        assert_eq!(
            verify_certificate(&issuer, &community, epoch, &leaf, &signature),
            Err(Error::Signature)
        );
    }
    let mut tampered = signature;
    tampered[0] ^= 1;
    assert_eq!(
        verify_certificate(&key, &[1; 32], 2, &leaf, &tampered),
        Err(Error::Signature)
    );
    for signature in [vec![], signature[..63].to_vec(), vec![0; 65]] {
        assert_eq!(
            verify_certificate(&key, &[1; 32], 2, &leaf, &signature),
            Err(Error::Signature)
        );
    }
    for (community, epoch, leaf) in [
        ([0; 32], 2, leaf),
        ([1; 32], 0, leaf),
        ([1; 32], MAX_INTEGER + 1, leaf),
        ([1; 32], 2, [0; 32]),
        ([1; 32], 2, [0xff; 32]),
    ] {
        assert_eq!(
            certificate_bytes(&community, epoch, &leaf),
            Err(Error::InvalidInput)
        );
    }
}

fn presentation(shares: Option<[u16; 3]>) -> czkp::record::Presentation {
    use czkp::record::{Context, Presentation, Record, Use, certificate_bytes, presentation_key};
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[7; 32]);
    let issuer = SigningKey::from_bytes(&[19; 32]);
    let record = Record {
        epoch: epoch(),
        owner: [9; 32],
        presentation_key: presentation_key(&key.verifying_key().to_bytes()),
        blinded_leaf: [1; 32],
        certificate: issuer
            .sign(&certificate_bytes(&[1; 32], 2, &[1; 32]).unwrap())
            .to_bytes()
            .to_vec(),
        shares,
    };
    let context = Context {
        purpose: Use::ForumListing,
        challenge: [8; 32],
        expires_at: 173000,
    };
    Presentation {
        signature: key
            .sign(&record.presentation_bytes(&context).unwrap())
            .to_bytes()
            .to_vec(),
        public_key: key.verifying_key().to_bytes(),
        record,
        context,
        // Syntax-only bytes. No proof verifier runs in these binding tests and
        // these bytes cannot be presented as a verified currentness capability.
        proof: "aabb".into(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn per_use_signatures_bind_purpose_challenge_expiry_and_shares() {
    use czkp::record::Use;
    let good = presentation(Some([1000, 2000, 7000]));
    good.check_binding(&good.context, &epoch(), &[9; 32], 172999)
        .unwrap();
    assert_eq!(
        good.check_binding(&good.context, &epoch(), &[9; 32], 173000),
        Err(Error::Expired)
    );
    for case in 0..4 {
        let mut tampered = good.clone();
        match case {
            0 => tampered.context.purpose = Use::FirstContact,
            1 => tampered.context.challenge[0] ^= 1,
            2 => tampered.context.expires_at += 1,
            3 => tampered.record.shares = Some([2000, 1000, 7000]),
            _ => unreachable!(),
        }
        // Even a caller expecting the substituted context cannot authenticate
        // the original per-use signature against those changed bytes.
        assert_eq!(
            tampered.check_binding(&tampered.context, &epoch(), &[9; 32], 172900),
            Err(Error::Signature)
        );
    }
    let mut first_contact = good;
    first_contact.context.purpose = Use::FirstContact;
    use ed25519_dalek::{Signer, SigningKey};
    first_contact.signature = SigningKey::from_bytes(&[7; 32])
        .sign(
            &first_contact
                .record
                .presentation_bytes(&first_contact.context)
                .unwrap(),
        )
        .to_bytes()
        .to_vec();
    first_contact
        .check_binding(&first_contact.context, &epoch(), &[9; 32], 172900)
        .unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn presentation_framing_refuses_malformed_proofs_and_invalid_metadata() {
    let good = presentation(None);
    for proof in [
        String::new(),
        "a".into(),
        "ag".into(),
        "ab".repeat(4 * 1024 * 1024 + 1),
    ] {
        let mut malformed = good.clone();
        malformed.proof = proof;
        assert_eq!(
            malformed.check_binding(&good.context, &epoch(), &[9; 32], 172900),
            Err(Error::InvalidInput)
        );
    }
    let mut maximum = good.clone();
    maximum.proof = "ab".repeat(4 * 1024 * 1024);
    // Exact shape bound only: neither hexadecimal form nor a valid binding
    // authenticates these uninterpreted bytes as a zero-knowledge proof.
    maximum
        .check_binding(&good.context, &epoch(), &[9; 32], 172900)
        .unwrap();

    for case in 0..7 {
        let mut invalid = good.record.clone();
        match case {
            0 => invalid.epoch.policy_epoch = 0,
            1 => invalid.owner = [0; 32],
            2 => invalid.presentation_key = [0; 32],
            3 => invalid.blinded_leaf = [0; 32],
            4 => invalid.blinded_leaf = [0xff; 32],
            5 => invalid.certificate.truncate(63),
            6 => invalid.shares = Some([10000, 10000, 0]),
            _ => unreachable!(),
        }
        assert_eq!(invalid.validate(), Err(Error::InvalidInput));
    }
    for context in [
        czkp::record::Context {
            challenge: [0; 32],
            ..good.context.clone()
        },
        czkp::record::Context {
            expires_at: epoch().starts_at,
            ..good.context.clone()
        },
        czkp::record::Context {
            expires_at: epoch().expires_at + 1,
            ..good.context.clone()
        },
        czkp::record::Context {
            expires_at: MAX_INTEGER + 1,
            ..good.context.clone()
        },
    ] {
        assert_eq!(
            good.record.presentation_bytes(&context),
            Err(Error::InvalidInput)
        );
    }
    let mut wire = serde_json::to_value(&good).unwrap();
    wire["current"] = serde_json::json!(true);
    assert!(serde_json::from_value::<czkp::record::Presentation>(wire).is_err());
}
