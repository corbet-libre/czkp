//! Certificate transcript vectors, shared golden signer vector and verification bounds.
use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn sign(secret: u8, bytes: &[u8]) -> [u8; 64] {
    let key = SigningKey::from_slice(&[secret; 32]).unwrap();
    let signature: Signature = key.sign(bytes);
    signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into()
}

fn public(secret: u8) -> [u8; 64] {
    let key = SigningKey::from_slice(&[secret; 32]).unwrap();
    key.verifying_key().to_encoded_point(false).as_bytes()[1..]
        .try_into()
        .unwrap()
}

fn state() -> AcceptedState {
    AcceptedState {
        community: [1; 32],
        identity: [5; 32],
        owner: [2; 32],
        state: [3; 32],
        scope: [4; 32],
        version: 7,
        accepted_at: 120,
    }
}

// cssr's tests sign exactly this transcript with issuer key [3; 32] and pin
// this public key and signature. Verifying them here, with this encoder,
// detects any divergence between the signer's input and the verifier.
const GOLDEN_TRANSCRIPT: &str = "637373722e61636365707465642d73746174652e7632000101010101010101010101010101010101010101010101010101010101010101050505050505050505050505050505050505050505050505050505050505050502020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040400000000000000070000000000000078";
const GOLDEN_PUBLIC_KEY: &str = "591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0";
const GOLDEN_SIGNATURE: &str = "5d7dce889d4477d54367b52f8182d46fe42e32b0ade5ff27213dc2d4df38921323c1d7e787bbf99db619b8bd4f716d2fe6715d4c934466931d9eac98f96519a3";

#[test]
fn the_signer_golden_vector_verifies_with_this_encoder() {
    assert_eq!(state().bytes(), hex(GOLDEN_TRANSCRIPT));
    let key: [u8; 64] = hex(GOLDEN_PUBLIC_KEY).try_into().unwrap();
    let signature: [u8; 64] = hex(GOLDEN_SIGNATURE).try_into().unwrap();
    state().verify(&key, &signature).unwrap();
    assert_eq!(key, public(3));
    assert_eq!(signature, sign(3, &state().bytes()));
}

#[test]
fn accepted_state_binds_every_field_and_the_key() {
    let signature = sign(3, &state().bytes());
    let key = public(3);
    for field in 0..7 {
        let mut changed = state();
        match field {
            0 => changed.community[0] ^= 1,
            6 => changed.identity[0] ^= 1,
            1 => changed.owner[0] ^= 1,
            2 => changed.state[0] ^= 1,
            3 => changed.scope[0] ^= 1,
            4 => changed.version += 1,
            _ => changed.accepted_at += 1,
        }
        assert!(changed.verify(&key, &signature).is_err());
    }
    assert!(state().verify(&public(4), &signature).is_err());
    assert!(state().verify(&[0; 64], &signature).is_err());
    assert!(state().verify(&key, &[0; 64]).is_err());
    let canonical = Signature::from_slice(&signature).unwrap();
    let (r, s) = canonical.split_scalars();
    let high = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    assert!(high.normalize_s().is_some());
    assert!(state().verify(&key, &high.to_bytes().into()).is_err());
}

fn ancestry() -> EpochAncestry {
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
        issued_at: 10,
    }
}

#[test]
fn ancestry_transcript_vector_and_every_field_are_bound() {
    let body = ancestry();
    let raw = hex(concat!(
        "63626c632e65706f63682d616e6365737472792e763100",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0000000000000003",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "0505050505050505050505050505050505050505050505050505050505050505",
        "0606060606060606060606060606060606060606060606060606060606060606",
        "0000000000000007",
        "0808080808080808080808080808080808080808080808080808080808080808",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "000000000000000a",
    ));
    assert_eq!(body.bytes().unwrap(), crate::compact::message(&raw));
    let signature = sign(3, &body.bytes().unwrap());
    body.verify(&public(3), &signature).unwrap();
    for field in 0..10 {
        let mut changed = ancestry();
        match field {
            0 => changed.community[0] ^= 1,
            1 => changed.owner[0] ^= 1,
            2 => changed.epoch += 1,
            3 => changed.root[0] ^= 1,
            4 => changed.frozen_leaf[0] ^= 1,
            5 => changed.state[0] ^= 1,
            6 => changed.version += 1,
            7 => changed.circuit_digest[0] ^= 1,
            8 => changed.verifying_key_digest[0] ^= 1,
            _ => changed.issued_at += 1,
        }
        assert!(changed.verify(&public(3), &signature).is_err());
    }
    // A state certificate signature is never ancestry evidence.
    let accepted = AcceptedState {
        community: body.community,
        identity: body.community,
        owner: body.owner,
        state: body.state,
        scope: body.circuit_digest,
        version: body.version,
        accepted_at: body.issued_at,
    };
    let confused = sign(3, &accepted.bytes());
    assert!(body.verify(&public(3), &confused).is_err());
    assert!(accepted.verify(&public(3), &signature).is_err());
}

#[test]
fn malformed_ancestry_bounds_cannot_be_encoded() {
    let max = (1 << 53) - 1;
    for field in 0..12 {
        let mut body = ancestry();
        match field {
            0 => body.community = [0; 32],
            1 => body.owner = [0; 32],
            2 => body.root = [0; 32],
            3 => body.frozen_leaf = [0; 32],
            4 => body.state = [0; 32],
            5 => body.circuit_digest = [0; 32],
            6 => body.verifying_key_digest = [0; 32],
            7 => body.epoch = 0,
            8 => body.epoch = 1 << 53,
            9 => body.version = 1 << 53,
            10 => body.issued_at = 0,
            _ => body.issued_at = 1 << 53,
        }
        assert!(body.bytes().is_err());
        assert!(body.verify(&public(3), &[1; 64]).is_err());
    }
    let mut boundary = ancestry();
    boundary.epoch = max;
    boundary.version = 0;
    boundary.issued_at = max;
    let signature = sign(3, &boundary.bytes().unwrap());
    boundary.verify(&public(3), &signature).unwrap();
}
#[test]
fn the_largest_circuit_integer_version_encodes() {
    let mut body = ancestry();
    body.version = (1 << 53) - 1;
    let bytes = body.bytes().unwrap();
    let signature = sign(3, &bytes);
    body.verify(&public(3), &signature).unwrap();
}

/// Verification known answers pinned before the move to p256 0.14 (RUSTSEC-2026-0387):
/// the same stored signatures must be accepted or refused identically. RFC 6979 A.2.5
/// key (low-S forms of 'sample' and 'test'), the golden issuer key, and the largest
/// scalar n-1; values cross-checked against OpenSSL.
mod vectors {
    use super::{hex, verify_bytes};

    const RFC_KEY: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    const MAX_KEY: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a";
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    /// (key, message, low-S signature, the same signature's high-S alias)
    const STORED: [(&str, &[u8], &str, &str); 3] = [
        (
            RFC_KEY,
            b"sample",
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf37160834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        ),
        (
            RFC_KEY,
            b"test",
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367fe60beeb8bd5d4ec42da6d94b639b6ea5dc07c4cd3965338e6f1887217f424ce",
        ),
        (
            MAX_KEY,
            b"sample",
            "a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ce487c55a869992245fa2f5a4631e74d8a41bf17b70262ece10f04fbf0dd21b09f",
            "a2e09df104aafc802a50c6684f6db83355a0a2588585a778b311e7e6c7c600ceb783aa569666ddbb05d0a5b9ce18b2757b27e2f6a4b4b1a3e4b4ced21f4174b2",
        ),
    ];

    fn array<const N: usize>(value: &str) -> [u8; N] {
        hex(value).try_into().unwrap()
    }

    #[test]
    fn stored_signatures_keep_their_verdicts() {
        for (key, message, low, high) in STORED {
            let key = array::<64>(key);
            assert!(verify_bytes(&key, message, &array(low)).is_ok());
            // The high-S alias is a second wire encoding and stays refused.
            assert!(verify_bytes(&key, message, &array(high)).is_err());
            let mut other = message.to_vec();
            other[0] ^= 1;
            assert!(verify_bytes(&key, &other, &array(low)).is_err());
            let mut flipped = array::<64>(low);
            flipped[63] ^= 1;
            assert!(verify_bytes(&key, message, &flipped).is_err());
        }
        let golden = (
            array::<64>(super::GOLDEN_PUBLIC_KEY),
            hex(super::GOLDEN_TRANSCRIPT),
            array::<64>(super::GOLDEN_SIGNATURE),
        );
        assert!(verify_bytes(&golden.0, &golden.1, &golden.2).is_ok());
    }

    #[test]
    fn malformed_keys_and_scalars_are_refused() {
        let (key, message, low, _) = STORED[0];
        let key = array::<64>(key);
        let low = array::<64>(low);
        // Zero or out-of-range r and s.
        for (offset, value) in [
            (0, [0u8; 32]),
            (32, [0u8; 32]),
            (0, array(ORDER)),
            (32, array(ORDER)),
        ] {
            let mut signature = low;
            signature[offset..offset + 32].copy_from_slice(&value);
            assert!(verify_bytes(&key, message, &signature).is_err());
        }
        // A point off the curve, and (0, 0).
        let mut off = key;
        off[63] ^= 1;
        assert!(verify_bytes(&off, message, &low).is_err());
        assert!(verify_bytes(&[0; 64], message, &low).is_err());
    }
}
