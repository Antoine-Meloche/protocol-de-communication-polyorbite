pub struct GaloisField {
    pub exp: [u8; 256],
    pub log: [u8; 256],
}

impl GaloisField {
    pub fn new() -> GaloisField {
        let mut exp = [0u8; 256];
        let mut log = [0u8; 256];

        let mut x: u16 = 1;
        for i in 0..256 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;

            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }

        GaloisField {
            exp: exp,
            log: log,
        }
    }

    pub fn add(a: u8, b: u8) -> u8 {
        return a ^ b;
    }

    pub fn multiply(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }

        let log_sum = self.log[a as usize] as usize + self.log[b as usize] as usize;
        return self.exp[log_sum % 255];
    }

    pub fn divide(&self, a: u8, b:u8) -> u8 {
        if b == 0 {
            return 0;
        }

        if a == 0 {
            return 0;
        }

        let log_diff = (self.log[a as usize] as i16 - self.log[b as usize] as i16 + 255) % 255;
        return self.exp[log_diff as usize];
    }
}