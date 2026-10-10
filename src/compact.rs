//! Versioned canonical byte packing around maintained Poseidon2; no permutation
//! or signature implementation. Every original transcript byte remains bound.

/// Hash a length-prefixed transcript in injective 31-byte BN254 field chunks.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut domain = [0; 32];
    let label = b"cblc.compact.v1";
    domain[32 - label.len()..].copy_from_slice(label);
    let mut fields = vec![domain, crate::poseidon::integer(bytes.len() as u64)];
    for chunk in bytes.chunks(31) {
        let mut field = [0; 32];
        field[1..1 + chunk.len()].copy_from_slice(chunk);
        fields.push(field);
    }
    crate::poseidon::hash(&fields).expect("31-byte limbs and domain are canonical fields")
}
/// Fixed-width message for standard P-256/SHA-256 signing in WebCrypto/RustCrypto.
pub fn message(bytes: &[u8]) -> Vec<u8> {
    let mut message = b"cblc.compact.v1\0".to_vec();
    message.extend_from_slice(&hash(bytes));
    message
}
