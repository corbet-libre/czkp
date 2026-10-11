//! Statement and acceptance vectors shared with the wallet holder and the Balance
//! operator: the same fixed fields, message digest and operator signature are
//! asserted by every consumer's tests.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

const GOLDEN_MESSAGE_DIGEST: &str =
    "a9189a36a90839b5a224f459ea8ca880194d26f4f439b2ace7b70e912bf8bc3a";
const GOLDEN_OPERATOR: &str = "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1";
const GOLDEN_SIGNATURE: &str = "1f722ba31f953dc655a6f1247d616798bd8d227427c3cf1358bf780082a3012db4ea429443439188e9c14ff78fa56f7a2dd38bce7e7d04273d016022f2562f08";
const POLICY_DIGEST: &str = "0031cb6451b5d91ff6301197873a4d02206a1d2144b7f7b3e909fb4b5c60188f";
const STATEMENT_DIGEST: &str = "3ac57a9da0ddc4101294e1a3c7f2fdae6a2bb3710c48f15a87c0ed264252b442";

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

fn statement() -> StatementFields {
    let (mut root, mut next) = ([0; 32], [0; 32]);
    root[31] = 7;
    next[31] = 9;
    StatementFields {
        protocol_version: 2,
        community: Sha256::digest(b"community").into(),
        owner: [2; 32],
        policy_digest: hex(POLICY_DIGEST).try_into().unwrap(),
        enrollment_root: root,
        now: 101,
        valid_until: 200,
        genesis: true,
        previous_version: 0,
        next_version: 0,
        previous_state: [0; 32],
        next_state: next,
        settlement_marker: [0; 32],
        policy: PolicyFields {
            initial_credit: 20,
            maximum_available: 100,
            outgoing_reservation: 5,
            incoming_reservation: 5,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 10_000,
            newcomer_period: 100,
            rate_window: 100,
            newcomer_admissions: 2,
            maximum_admissions: 10,
            refill_period: 100,
            refill_units: 2,
            abandon_after: 200,
        },
    }
}

fn scope() -> ProofScope {
    ProofScope {
        circuit_digest: [0xC3; 32],
        verifying_key_digest: [0xD4; 32],
    }
}

fn message(at: u64, statement: &StatementFields) -> Vec<u8> {
    acceptance_bytes(&[0xA1; 32], &[0xB2; 32], &scope(), at, statement)
}

#[test]
fn golden_statement_message_and_signature_are_pinned() {
    // SHA-256 of the statement transcript, computed outside this crate.
    assert_eq!(
        Sha256::digest(statement().bytes()).to_vec(),
        hex(STATEMENT_DIGEST)
    );
    let bytes = message(150, &statement());
    assert_eq!(Sha256::digest(&bytes).to_vec(), hex(GOLDEN_MESSAGE_DIGEST));
    let key: [u8; 32] = hex(GOLDEN_OPERATOR).try_into().unwrap();
    let signature: [u8; 64] = hex(GOLDEN_SIGNATURE).try_into().unwrap();
    verify_acceptance(&bytes, &key, &signature).unwrap();
    assert_eq!(
        key,
        SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes()
    );
    assert_eq!(
        signature,
        SigningKey::from_bytes(&[5; 32]).sign(&bytes).to_bytes()
    );
    assert_eq!(
        acceptance_digest(&bytes, &signature).to_vec(),
        Sha256::digest([bytes.as_slice(), signature.as_slice()].concat()).to_vec()
    );
}

#[test]
fn every_acceptance_field_and_the_key_are_bound() {
    let key: [u8; 32] = hex(GOLDEN_OPERATOR).try_into().unwrap();
    let signature: [u8; 64] = hex(GOLDEN_SIGNATURE).try_into().unwrap();
    assert!(verify_acceptance(&message(151, &statement()), &key, &signature).is_err());
    let mut changed = statement();
    changed.next_state[0] ^= 1;
    assert!(verify_acceptance(&message(150, &changed), &key, &signature).is_err());
    changed = statement();
    changed.policy.abandon_after += 1;
    assert!(verify_acceptance(&message(150, &changed), &key, &signature).is_err());
    let mut other = key;
    other[0] ^= 1;
    assert!(verify_acceptance(&message(150, &statement()), &other, &signature).is_err());
    let mut bad = signature;
    bad[63] ^= 1;
    assert!(verify_acceptance(&message(150, &statement()), &key, &bad).is_err());
    let mut id = acceptance_bytes(&[0xA2; 32], &[0xB2; 32], &scope(), 150, &statement());
    assert!(verify_acceptance(&id, &key, &signature).is_err());
    id = acceptance_bytes(&[0xA1; 32], &[0xB3; 32], &scope(), 150, &statement());
    assert!(verify_acceptance(&id, &key, &signature).is_err());
    let mut wide = scope();
    wide.verifying_key_digest[0] ^= 1;
    id = acceptance_bytes(&[0xA1; 32], &[0xB2; 32], &wide, 150, &statement());
    assert!(verify_acceptance(&id, &key, &signature).is_err());
    // Small-order keys are refused by strict verification.
    assert!(verify_acceptance(&message(150, &statement()), &[0; 32], &signature).is_err());
}
