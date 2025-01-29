use ascon_aead::{
    aead::{Aead, KeyInit},
    Ascon128, Key, Nonce,
};

#[cfg(feature = "ground-station")]
use rand::random;

use crate::pack::compute_crc;

#[cfg(feature = "ground-station")]
pub fn sign_data(data: &[u8], key_raw: &[u8; 16]) -> Vec<u8> {
    use crate::pack::compute_crc;

    let mut result = Vec::with_capacity(data.len() + 48);
    result.extend_from_slice(&data);

    let hash: [u8; 16] = md5::compute(data).0;
    let crc: [u8; 2] = compute_crc(data).to_be_bytes();

    let mut plaintext = [0u8; 18];
    plaintext[0..16].copy_from_slice(&hash);
    plaintext[16..].copy_from_slice(&crc);

    let nonce: [u8; 16] = random();

    let key = Key::<Ascon128>::from_slice(key_raw);
    let cipher = Ascon128::new(key);
    let nonce_ref = Nonce::<Ascon128>::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce_ref, plaintext.as_ref()).unwrap();

    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&nonce);

    return result;
}

pub fn verify_data(signed_data: &[u8], key_raw: &[u8; 16]) -> bool {
    if signed_data.len() < 50 {
        return false;
    }

    let data_len = signed_data.len() - 50;
    let data = &signed_data[..data_len];

    let encrypted_hash = &signed_data[data_len..data_len + 34];
    let nonce = &signed_data[data_len + 34..];

    let expected_hash: [u8; 16] = md5::compute(data).0;
    let expected_crc: [u8; 2] = compute_crc(data).to_be_bytes();

    let key = Key::<Ascon128>::from_slice(key_raw);
    let cipher = Ascon128::new(key);
    let nonce_ref = Nonce::<Ascon128>::from_slice(nonce);

    return match cipher.decrypt(nonce_ref, encrypted_hash) {
        Ok(decrypted) => {
            let decrypted_hash = &decrypted[0..16];
            let decrypted_crc = &decrypted[16..];
            return decrypted_hash == expected_hash && decrypted_crc == expected_crc;
        }
        Err(_) => false,
    };
}
