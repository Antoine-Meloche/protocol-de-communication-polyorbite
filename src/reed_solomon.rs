use crate::gf::GF256;
use crate::pack::Bytes;

const N: usize = 255;
const K: usize = 191;
const T: usize = 32;
const N_K: usize = N - K;

#[derive(Debug)]
pub struct ReedSolomon {
    generator: [GF256; N_K + 1],
}

impl ReedSolomon {
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

    pub fn encode(&self, message: &[u8]) -> [u8; N] {
        debug_assert!(message.len() == K); // FIXME: remove assert to remove possibility of panic
        
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
        
        return temp;
    }

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