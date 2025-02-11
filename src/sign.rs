//! # Data Signing & Verification Tools
//!
//! This module provides functionality for signing and verifying data using Ascon128 AE encryption, MD5 hashing, and CRC checks.
//!
//! Two main functions are provided:
//! - `sign_data()` - Creates a cryptographic signature for input data using an encryption key
//! - `verify_data()` - Verifies the signature matches the data using the same key
//!
//! ## The signing process:
//! 1. Computes MD5 hash and CRC of input data
//! 2. Encrypts hash+CRC with Ascon128 using provided key and random nonce
//! 3. Returns combined ciphertext + nonce
//!
//! ## The verification process:
//! 1. Splits signature into ciphertext and nonce
//! 2. Decrypts using key and nonce
//! 3. Compares decrypted hash+CRC against fresh hash+CRC of data
//! 4. Returns true if everything matches
//!
//! Signatures are fixed length 50 bytes containing:
//! - 34 bytes encrypted data (hash + CRC)
//! - 16 bytes nonce

use ascon_aead::{
    aead::{Aead, KeyInit},
    Ascon128, Key, Nonce,
};

#[cfg(feature = "ground-station")]
use rand::random;

use crate::pack::compute_crc;

/// # Sign data by encrypting an MD5 hash and CRC using Ascon128 encryption.
///
/// ## Arguments
/// * `data` - The input data bytes to sign
/// * `key_raw` - The 16-byte encryption key
///
/// ## Returns
/// A 50-byte signature containing:
/// * Bytes 0-33: Encrypted hash+CRC ciphertext
/// * Bytes 34-49: Random nonce used for encryption
///
/// The signing process:
/// 1. Computes MD5 hash and CRC32 of input data
/// 2. Combines hash and CRC into single plaintext buffer
/// 3. Generates random 16-byte nonce
/// 4. Encrypts plaintext using key and nonce
/// 5. Returns concatenated ciphertext and nonce
///
/// This function is only available when the "ground-station" feature is enabled.
///
/// ## Example
/// ```
/// use comms::sign::sign_data;
///
/// let data = b"Hello world!";
///
/// // 16-byte encryption key
/// let key = [0x42; 16];
///
/// // Sign the data
/// let signature = sign_data(data, &key);
/// ```
#[cfg(feature = "ground-station")]
pub fn sign_data(data: &[u8], key_raw: &[u8; 16]) -> [u8; 50] {
    let mut result = [0u8; 50];

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

    result[0..34].copy_from_slice(&ciphertext);
    result[34..].copy_from_slice(&nonce);

    return result;
}

/// # Verify data's signature matches by checking hash and CRC values.
///
/// ## Arguments
/// * `signed_data` - The original data being verified
/// * `signature` - The 50-byte signature from sign_data()
/// * `key_raw` - The 16-byte encryption key used for signing
///
/// ## Returns
/// Boolean indicating whether signature matches the data:
/// * true - Signature is valid
/// * false - Signature fails verification
///
/// The verification process:
/// 1. Splits signature into ciphertext (34 bytes) and nonce (16 bytes)
/// 2. Computes current MD5 hash and CRC32 of input data
/// 3. Decrypts signature using key and nonce
/// 4. Compares decrypted hash+CRC against current values
/// 5. Returns true only if everything matches
///
/// ## Example
/// ```
/// use comms::sign::{verify_data, sign_data};
///
/// let data = b"Hello world!";
/// let key = [0x42; 16];
/// let signature = sign_data(data, &key);
///
/// // Verify the signature
/// let is_valid = verify_data(data, signature, &key);
/// assert!(is_valid);
/// ```
pub fn verify_data(signed_data: &[u8], signature: [u8; 50], key_raw: &[u8; 16]) -> bool {
    if signature.len() != 50 {
        return false;
    }

    let encrypted_hash = &signature[0..34];
    let nonce = &signature[34..];

    let expected_hash: [u8; 16] = md5::compute(signed_data).0;
    let expected_crc: [u8; 2] = compute_crc(signed_data).to_be_bytes();

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
