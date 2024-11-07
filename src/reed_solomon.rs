use crate::{gf::GaloisField, pack::Bytes};

pub struct ReedSolomon {
    pub gf: GaloisField,
    pub generator: [u8; 64],
    pub n: usize,
    pub k: usize,
    pub t: usize,
}

impl ReedSolomon {
    pub fn new() -> ReedSolomon {
        let mut rs: ReedSolomon = ReedSolomon {
            gf: GaloisField::new(),
            generator: [0u8; 64],
            n: 255,
            k: 191,
            t: 32,
        };

        rs.generator[0] = 1;
        for i in 0..64 {
            for j in (0..=i).rev() {
                let mut tmp = rs.generator[j];
                if j > 0 {
                    tmp = rs.gf.add(tmp, rs.gf.multiply(rs.generator[j-1], rs.gf.exp[i]));
                }
                rs.generator[j] = tmp;
            }
        }

        return rs;
    }

    pub fn encode(&self, data: [u8; 255]) -> [u8; 255] {
        return [0u8; 255];
    }
}
