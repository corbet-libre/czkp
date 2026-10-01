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
    assert!(decode::<32>(&"!".repeat(43)).is_err());
    assert!(decode::<64>(&"!".repeat(86)).is_err());
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

#[cfg(feature = "schema")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn proof_scope_schema_follows_the_wire_owner() {
    use utoipa::{PartialSchema, ToSchema};
    let schema = serde_json::to_value(czkp::ProofScope::schema()).unwrap();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    for name in ["circuitDigest", "verifyingKeyDigest"] {
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == name)
        );
        assert_eq!(schema["properties"][name]["type"], "array");
    }
    assert_eq!(czkp::ProofScope::name(), "ProofScope");
    let mut referenced = Vec::new();
    czkp::ProofScope::schemas(&mut referenced);
    let json_schema = serde_json::to_value(schemars::schema_for!(czkp::ProofScope)).unwrap();
    assert_eq!(json_schema["additionalProperties"], false);
    for name in ["circuitDigest", "verifyingKeyDigest"] {
        assert_eq!(json_schema["properties"][name]["minItems"], 32);
        assert_eq!(json_schema["properties"][name]["maxItems"], 32);
    }
}
