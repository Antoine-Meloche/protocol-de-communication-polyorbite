pub struct GaloisField {
    pub exp: [u8; 256],
    pub log: [u8; 256],
}

impl GaloisField {
    pub fn new() -> GaloisField {
        let mut gf = GaloisField{
            exp: [0u8; 256],
            log: [0u8; 256]
        };
        let mut value: u16 = 1;

        for i in 0..255 {
            gf.exp[i] = value as u8;
            gf.log[value as usize - 1] = i as u8;

            value <<= 1;

            if value & 0x100 != 0 {
                value = value ^ 0x11B;
            }
        }

        gf.exp[255] = gf.exp[0];

        return gf;
    }

    pub fn add(&self, a: u8, b: u8) -> u8 {
        return a ^ b;
    }

    pub fn multiply(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }

        let log_sum = ((self.log[a as usize] as u16 + self.log[b as usize] as u16) % 255) as u8;
        return self.exp[log_sum as usize];
    }

    pub fn inverse(&self, a: u8) -> u8 {
        if a == 0 {
            unreachable!("");
        }

        return self.exp[255 - self.log[a as usize] as usize];
    }

    pub fn divide(&self, a: u8, b:u8) -> u8 {
        if b == 0 {
            return 0;
        }

        return self.multiply(a, self.inverse(b));
    }
}