#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GF256(pub u8);

impl GF256 {
    const POLYNOMIAL: u16 = 0x11d;

    #[inline]
    pub const fn new(value: u8) -> Self {
        return Self(value);
    }

    pub fn multiply(mut a: u8, mut b: u8) -> u8 {
        let mut result: u8 = 0;

        for _ in 0..8 {
            if (a & 0x01) != 0 {
                result ^= b;
            }

            let high_bit = b & 0x80;
            b <<= 1;

            if high_bit != 0 {
                b ^= (Self::POLYNOMIAL & 0xff) as u8;
            }

            a >>= 1;
        }

        return result;
    }

    pub fn inverse(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }

        let mut result = a;
        for i in 0..7 {
            result = Self::multiply(result, result);

            if i != 6 {
                result = Self::multiply(result, a);
            }
        }

        return result;
    }

    pub fn divide(a: u8, b: u8) -> u8 {
        if b == 0 {
            return 0;
        }

        return Self::multiply(a, Self::inverse(b));
    }
}

impl core::ops::Add for GF256 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        return GF256(self.0 ^ rhs.0);
    }
}

impl core::ops::Sub for GF256 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        return GF256(self.0 ^ rhs.0);
    }
}

impl core::ops::Mul for GF256 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        GF256(Self::multiply(self.0, rhs.0))
    }
}

impl core::ops::Div for GF256 {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self {
        return GF256(Self::divide(self.0, rhs.0));
    }
}