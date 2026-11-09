//! Original compact transcript encoding around the real maintained Poseidon2.
//! Hashes and encoded messages alone grant no proof or accounting authority.
use czkp::{compact, field};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn compact_transcripts_bind_length_zeros_and_chunk_boundaries() {
    for (left, right) in [
        (vec![], vec![0]),
        (vec![1], vec![1, 0]),
        (vec![1], vec![0, 1]),
        (vec![0; 31], vec![0; 32]),
        (vec![1; 31], vec![1; 32]),
        (vec![0; 62], vec![0; 63]),
    ] {
        assert_ne!(compact::hash(&left), compact::hash(&right));
    }
    for length in [0, 1, 30, 31, 32, 62, 63, 64] {
        let bytes = vec![0xff; length];
        let hash = compact::hash(&bytes);
        field(&hash, false).unwrap();
        let message = compact::message(&bytes);
        let prefix = b"cblc.compact.v1\0";
        assert_eq!(message.len(), prefix.len() + 32);
        assert_eq!(&message[..prefix.len()], prefix);
        assert_eq!(&message[prefix.len()..], hash);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_original_transcript_byte_affects_the_compact_message() {
    let bytes: Vec<u8> = (0..63).collect();
    let original = compact::message(&bytes);
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert_ne!(compact::message(&changed), original);
    }
}
