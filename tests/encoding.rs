//! Identical native and wasm vectors for the maintained cryptographic adapters.
use czkp::{Error, decode, digest, field, scope, signature};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signatures_and_canonical_encodings() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = B64.encode(&key.verifying_key().to_bytes());
    let signed = B64.encode(&key.sign(b"statement").to_bytes());
    assert_eq!(signature(&public, b"statement", &signed), Ok(()));
    assert_eq!(
        signature(&public, b"tampered", &signed),
        Err(Error::Signature)
    );
    assert_eq!(
        signature("", b"statement", &signed),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        signature(&public, b"statement", ""),
        Err(Error::InvalidInput)
    );
    let invalid = (0..=255)
        .map(|b| [b; 32])
        .find(|v| ed25519_dalek::VerifyingKey::from_bytes(v).is_err())
        .unwrap();
    assert_eq!(
        signature(&B64.encode(&invalid), b"statement", &signed),
        Err(Error::Signature)
    );
    assert!(decode::<32>(&(public + "=")).is_err());
    assert!(decode::<1>("__").is_err()); // Nonzero unused trailing bits.
    assert!(decode::<1>("A!").is_err());
    assert_eq!(decode::<1>("AA"), Ok([0]));
    assert_eq!(decode::<0>(""), Ok([]));
    assert!(field(&[255; 32], false).is_err());
    assert!(field(&[0; 32], true).is_err());
    assert!(field(&[0; 32], false).is_ok());
    assert!(field(&[1; 32], true).is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scopes_hashes_and_diagnostics() {
    assert!(scope("cblc.account:v1/TEST-._012"));
    for invalid in ["", "has space", "\u{00e9}", &"a".repeat(257)] {
        assert!(!scope(invalid));
    }
    assert!(scope(&"a".repeat(256)));
    assert_eq!(
        digest(b"abc"),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );
    assert_eq!(Error::InvalidInput.to_string(), "InvalidInput");
    assert!(std::error::Error::source(&Error::Signature).is_none());
}
