use crate::gf::GaloisField;

pub struct ReedSolomon {
    gf: GaloisField,
    generator: [u8; 64],
}

impl ReedSolomon {
    pub fn new() -> ReedSolomon {
        let gf = GaloisField::new();

        let generator: [u8; 64] = [1; 64];
        for i in 0..64 {
            let mut next_gen: [u8; 64] = [0; 64];

            for j in 0..=i {
                next_gen[j] = gf.multiply(generator[j], gf.exp[i as usize]);

                if j < i {
                    next_gen[j] ^= generator[j + 1];
                }
            }
        }

        ReedSolomon {
            gf: gf,
            generator: generator,
        }
    }

    pub fn encode(&self, message: [u8; 255]) -> [u8; 255] {
        let mut codeword: [u8; 255] = message;

        for i in 0..191 {
            let coeff = codeword[i];

            if coeff != 0 {
                for j in 0..64 {
                    codeword[i + j + 1] ^= self.gf.multiply(coeff, self.generator[j]);
                }
            }
        }

        return codeword;
    }
}