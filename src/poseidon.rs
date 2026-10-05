//! Canonical BN254 encodings around the maintained Poseidon2 Noir-compatible API.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use pso_poseidon::Poseidon2;

/// Split arbitrary bytes32 into two injective unsigned 128-bit field limbs.
pub fn limbs(value: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut out = [[0; 32]; 2];
    out[0][16..].copy_from_slice(&value[..16]);
    out[1][16..].copy_from_slice(&value[16..]);
    out
}
/// Encode an unsigned integer without field reduction.
pub fn integer(value: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}
/// Hash canonical field elements with the existing maintained `hash_noir` API.
pub fn hash(values: &[[u8; 32]]) -> Result<[u8; 32], crate::Error> {
    let inputs = values
        .iter()
        .map(|value| {
            crate::field(value, false)?;
            Ok(Fr::from_be_bytes_mod_order(value))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    let bytes = Poseidon2::<Fr>::new()
        .hash_noir(&inputs)
        .into_bigint()
        .to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}
