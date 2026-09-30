//! Integration tests for the public contract.
use czkp::{Error, decode, field, signature};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
#[test]
fn signatures_and_canonical_encodings() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = B64.encode(&key.verifying_key().to_bytes());
    let signed = B64.encode(&key.sign(b"statement").to_bytes());
    assert_eq!(signature(&public, b"statement", &signed), Ok(()));
    assert_eq!(
        signature(&public, b"tampered", &signed),
        Err(Error::Signature)
    );
    assert!(decode::<32>(&(public + "=")).is_err());
    assert!(field(&[255; 32], false).is_err());
    assert!(field(&[0; 32], true).is_err());
    assert!(field(&[0; 32], false).is_ok());
}
