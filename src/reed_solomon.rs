//! # Reed-Solomon Error Correction
//!
//! This is an implementation of the Reed-Solomon error correction algorithm,
//! commonly used in applications like QR codes, data storage, and digital communications.
//!
//! The implementation is parameterized with constants defining the codeword length (`N`), 
//! message length (`K`), and error correction capacity (`T`). It uses Galois Field arithmetic
//! over GF(256) for encoding and decoding operations.
//!
//! # Overview
//!
//! - **Encoding**: Transforms a message of length `K` into a codeword of length `N`.
//! - **Decoding**: Detects and corrects up to `T` errors in a received codeword of length `N`.
//! - **Key Components**:
//!     - **Syndrome Calculation**: Detects errors in a received codeword.
//!     - **Error Locator Polynomial**: Determines where errors occur.
//!     - **Error Correction**: Repairs errors in the codeword.
//!
//! # Usage
//!
//! ```
//! use comms::reed_solomon::ReedSolomon;
//! 
//! let rs = ReedSolomon::new();
//! 
//! let message: [u8; 191] = [42; 191];
//! 
//! if let Some(encoded_message) = rs.encode(&message) {
//!     let mut codeword = encoded_message;
//! 
//!     codeword[10] ^= 0xFF; // Corrupt one byte
//!     codeword[20] ^= 0xFF; // Corrupt another byte
//!     
//!     if let Some(decoded_message) = rs.decode(&mut codeword) {
//!         assert_eq!(decoded_message, message);
//!         println!("Decoding succeeded! Message: {:?}", decoded_message);
//!     } else {
//!         println!("Decoding failed: too many errors.");
//!     }
//! } else {
//!     println!("Encoding failed");
//! }
//! ```
use crate::gf::GF256;
use crate::pack::Bytes;

/// The total length of the codeword (message + parity bytes).
const N: usize = 255;

/// The length of the message to be encoded.
const K: usize = 191;

/// The number of correctable errors (T = (N - K) / 2).
const T: usize = 32;

/// The number of parity bytes added to the message (N - K).
const N_K: usize = N - K;

/// A Reed-Solomon encoder/decoder.
///
/// This struct encapsulates the functionality for encoding and decoding messages using
/// Reed-Solomon error correction. It precomputes and stores the generator polynomial used
/// for encoding.
///
/// # Fields
/// - `generator`: The generator polynomial coefficients used in encoding.
///
/// # Example
///
/// ```
/// use comms::reed_solomon::ReedSolomon;
/// 
/// let rs = ReedSolomon::new();
/// let message = [1u8; 191];
/// let codeword = rs.encode(&message);
/// println!("Codeword: {:?}", codeword);
/// ```
#[derive(Debug)]
pub struct ReedSolomon {
    generator: [GF256; N_K + 1],
}

impl ReedSolomon {
    /// Constructs a new `ReedSolomon` encoder/decoder with a generator polynomial.
    ///
    /// # Returns
    /// A `ReedSolomon` struct initialized with a generator polynomial.
    /// 
    /// # Example
    /// 
    /// ```
    /// use comms::reed_solomon::ReedSolomon;
    /// 
    /// let rs = ReedSolomon::new();
    /// ```
    pub fn new() -> Self {
        let mut generator: [GF256; 65] = [GF256(0); N_K + 1];
        generator[0] = GF256(1);
        
        let mut tmp: [GF256; 65] = [GF256(0); N_K + 1];
        
        for i in 0..N_K {
            for j in 0..=i {
                tmp[j] = generator[j];
            }
            
            for j in 0..=i {
                let alpha: GF256 = GF256(Self::exp_table(i as u8));
                generator[j+1] = generator[j+1] + tmp[j];
                generator[j] = tmp[j] * alpha;
            }
        }
        
        return Self { generator };
    }
    
    /// Computes the exponential table value for a given index.
    ///
    /// # Arguments
    /// - `i`: The index for which the exponential value is calculated.
    ///
    /// # Returns
    /// The computed exponential value as `u8`.
    const fn exp_table(i: u8) -> u8 {
        let mut result: u8 = 1u8;
        let mut j: u8 = 0;

        while j < i {
            result = if result & 0x80 != 0 {
                (result << 1) ^ 0x1D
            } else {
                result << 1
            };
            j += 1;
        }

        return result;
    }

    /// Encodes a given message into a Reed-Solomon codeword.
    ///
    /// # Arguments
    /// - `message`: A slice of bytes with length `K` (message length).
    ///
    /// # Returns
    /// An array of bytes of length `N` containing the encoded codeword.
    /// 
    /// # Example
    /// 
    /// ```
    /// use comms::reed_solomon::ReedSolomon;
    /// 
    /// let rs = ReedSolomon::new();
    /// 
    /// let mut message: [u8; 191] = [0u8; 191];
    /// for i in 0..191 {
    ///     message[i] = (i % 256) as u8;
    /// }
    /// 
    /// if let Some(encoded_message) = rs.encode(&message) {
    ///     println!("{:?}", encoded_message);
    /// } else {
    ///     println!("There was an error while trying to encode the message.");
    /// }
    /// ```
    pub fn encode(&self, message: &[u8]) -> Option<[u8; N]> {
        if message.len() != K {
            return None;
        }
        
        let mut codeword: [u8; 255] = [0u8; N];
        
        for i in 0..K {
            codeword[i] = message[i];
        }
        
        for i in 0..K {
            let coeff: GF256 = GF256(codeword[i]);
            if coeff.0 != 0 {
                for j in 0..N_K {
                    codeword[i + j + 1] ^= (coeff * self.generator[j + 1]).0;
                }
            }
        }
        
        let mut temp: [u8; 255] = [0u8; N];
        for i in 0..K {
            temp[N_K + i] = message[i];
        }
        for i in 0..N_K {
            temp[i] = codeword[K + i];
        }
        
        return Some(temp);
    }

    /// Calculates syndromes for the received codeword.
    ///
    /// # Arguments
    /// - `received`: A reference to an array of bytes of length `N` (received codeword).
    ///
    /// # Returns
    /// An array of syndromes of length `N_K`.
    fn calc_syndromes(&self, received: &[u8; N]) -> [GF256; N_K] {
        let mut synd: [GF256; 64] = [GF256(0); N_K];
        
        for i in 0..N_K {
            let mut accum: GF256 = GF256(0);
            let alpha_i: GF256 = GF256(Self::exp_table(i as u8));
            let mut power: GF256 = GF256(1);
            
            for j in (0..N).rev() {
                accum = accum + (GF256(received[j]) * power);
                power = power * alpha_i;
            }
            synd[i] = accum;
        }
        
        return synd;
    }

    /// Finds the error locator polynomial using the Berlekamp-Massey algorithm.
    ///
    /// # Arguments
    /// - `syndromes`: A reference to an array of syndromes of length `N_K`.
    ///
    /// # Returns
    /// A `Bytes` array representing the error locator polynomial.
    fn find_error_locator(&self, syndromes: &[GF256; N_K]) -> Bytes<{ N_K + 1 }> {
        let mut old_locator: Bytes<{ N_K + 1 }> = Bytes::<{ N_K + 1 }>::new();
        old_locator.push(GF256(1).0);
        
        let mut locator: Bytes<{ N_K + 1 }> = Bytes::<{ N_K + 1 }>::new();
        locator.push(GF256(1).0);
        
        let mut temp: Bytes<{ N_K + 1 }> = Bytes::<{ N_K + 1 }>::new();
        
        for i in 0..N_K {
            let delta: GF256 = {
                let mut sum: GF256 = GF256(0);
                for j in 0..locator.pointer {
                    sum = sum + (GF256(locator.bytes[j]) * syndromes[i - j]);
                }
                sum
            };
            
            old_locator.push(0);
            
            if delta.0 != 0 {
                temp.pointer = 0;
                for j in 0..old_locator.pointer {
                    temp.push(old_locator.bytes[j]);
                }
                
                for j in 0..locator.pointer {
                    temp.bytes[j] = (GF256(temp.bytes[j]) - (delta * GF256(locator.bytes[j]))).0;
                }
                
                if 2 * old_locator.pointer <= i + 2 {
                    old_locator.pointer = 0;
                    for j in 0..locator.pointer {
                        old_locator.push((GF256(locator.bytes[j]) * (GF256(1) / delta)).0);
                    }
                    
                    locator.pointer = 0;
                    for j in 0..temp.pointer {
                        locator.push(temp.bytes[j]);
                    }
                } else {
                    locator.pointer = 0;
                    for j in 0..temp.pointer {
                        locator.push(temp.bytes[j]);
                    }
                }
            }
        }
        
        return locator;
    }
    
    /// Identifies error locations in the received codeword based on the error locator polynomial.
    ///
    /// # Arguments
    /// - `error_locator`: A reference to the error locator polynomial.
    /// - `received_len`: The length of the received codeword.
    ///
    /// # Returns
    /// A `Bytes` array containing the indices of the errors.
    fn find_errors(&self, error_locator: &Bytes<{ N_K + 1 }>, received_len: usize) -> Bytes<T> {
        let mut errors = Bytes::<T>::new();
        
        for i in 0..received_len {
            let mut sum = GF256(0);
            let x_inv = GF256(Self::exp_table((255 - i) as u8));
            let mut power = GF256(1);
            
            for j in 0..error_locator.pointer {
                sum = sum + (GF256(error_locator.bytes[j]) * power);
                power = power * x_inv;
            }
            
            if sum.0 == 0 {
                errors.push(i as u8);
            }
        }
        
        errors
    }

    /// Corrects errors in the received codeword using the calculated syndromes and error positions.
    ///
    /// # Arguments
    /// - `received`: A mutable reference to the received codeword array of length `N`.
    /// - `syndromes`: A reference to an array of syndromes of length `N_K`.
    /// - `error_positions`: A reference to a `Bytes` array containing error positions.
    fn correct_errors(&self, received: &mut [u8; N], syndromes: &[GF256; N_K], error_positions: &Bytes<T>) {
        let mut error_evaluator: Bytes<{ N_K }> = Bytes::<{ N_K }>::new();
        let mut locator_derivative: Bytes<T> = Bytes::<T>::new();
        
        for i in 0..N_K {
            let mut sum: GF256 = GF256(0);
            for j in 0..=i {
                sum = sum + (syndromes[j] * syndromes[i - j]);
            }
            error_evaluator.push(sum.0);
        }
        
        for i in 0..error_positions.pointer {
            let pos: usize = error_positions.bytes[i] as usize;
            let x_inv: GF256 = GF256(Self::exp_table((255 - pos) as u8));
            let mut sum: GF256 = GF256(0);
            let mut power: GF256 = GF256(1);
            
            for j in 1..error_evaluator.pointer {
                sum = sum + (GF256(error_evaluator.bytes[j]) * power * GF256(j as u8));
                power = power * x_inv;
            }
            
            locator_derivative.push(sum.0);
        }
        
        for i in 0..error_positions.pointer {
            let pos: usize = error_positions.bytes[i] as usize;
            let x: GF256 = GF256(Self::exp_table(pos as u8));
            let magnitude: GF256 = (GF256(error_evaluator.bytes[i]) * x) / GF256(locator_derivative.bytes[i]);
            received[pos] ^= magnitude.0;
        }
    }

    /// Decodes a received Reed-Solomon codeword into the original message.
    ///
    /// # Arguments
    /// - `received`: A mutable reference to an array of bytes of length `N` (received codeword).
    ///
    /// # Returns
    /// An `Option` containing the decoded message as an array of bytes of length `K` if successful, 
    /// or `None` if decoding fails.
    /// 
    /// # Example
    /// ```
    /// use comms::reed_solomon::ReedSolomon;
    /// 
    /// let rs = ReedSolomon::new();
    /// 
    /// let message: [u8; 191] = [42; 191];
    /// 
    /// if let Some(encoded_message) = rs.encode(&message) {
    ///     let mut codeword = encoded_message;
    /// 
    ///     codeword[10] ^= 0xFF; // Corrupt one byte
    ///     codeword[20] ^= 0xFF; // Corrupt another byte
    ///     
    ///     if let Some(decoded_message) = rs.decode(&mut codeword) {
    ///         assert_eq!(decoded_message, message);
    ///         println!("Decoding succeeded! Message: {:?}", decoded_message);
    ///     } else {
    ///         println!("Decoding failed: too many errors.");
    ///     }
    /// } else {
    ///     println!("Encoding failed");
    /// }
    /// ```
    pub fn decode(&self, received: &mut [u8; N]) -> Option<[u8; K]> {
        let syndromes: [GF256; N_K] = self.calc_syndromes(received);
        
        if syndromes.iter().all(|&s| s.0 == 0) {
            let mut message: [u8; 191] = [0u8; K];
            message.copy_from_slice(&received[N_K..]);
            return Some(message);
        }
        
        let error_locator: Bytes<{ N_K + 1 }> = self.find_error_locator(&syndromes);
        
        let error_positions: Bytes<T> = self.find_errors(&error_locator, N);
        
        if error_positions.bytes.len() > T {
            return None;
        }
        
        self.correct_errors(received, &syndromes, &error_positions);
        
        let mut message = [0u8; K];
        message.copy_from_slice(&received[N_K..]);
        return Some(message);
    }
}