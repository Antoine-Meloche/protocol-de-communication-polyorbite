//! # This module provides an implementation of Galois Field (GF(2^8)) arithmetic
//!
//! The field is defined over the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
//! All operations (addition, subtraction, multiplication, division) are implemented using
//! efficient bit manipulation techniques.
//!
//! ## Features
//!
//! - Addition/subtraction using XOR operations
//! - Efficient multiplication using shift-and-add with polynomial reduction
//! - Division using multiplicative inverses computed via Fermat's Little Theorem
//! - Full operator overloading support (+, -, *, /)
//!
//! ## Examples
//!
//! ```
//! use comms::gf::GF256;
//!
//! // Create field elements
//! let a = GF256::new(0x53);
//! let b = GF256::new(0x0F);
//!
//! // Perform field arithmetic
//! let sum = a + b;
//! let product = a * b;
//! let quotient = a / b;
//! ```

/// # Represents an element in the Galois Field GF(2^8).
///
/// This implementation uses the primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
/// for field arithmetic. All operations are performed modulo this polynomial.
///
/// ## Examples
///
/// ```
/// use comms::gf::GF256;
///
/// let a = GF256(0x53);
/// let b = GF256(0x0F);
/// let c = a * b;  // Multiplication in GF(2^8)
/// let d = a + b;  // Addition in GF(2^8)
/// let e = a / b;  // Division in GF(2^8)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GF256(pub u8);

impl GF256 {
    /// The primitive polynomial used for field arithmetic: x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
    const POLYNOMIAL: u16 = 0x11d;

    /// # Creates a new GF256 element from a raw byte value.
    ///
    /// ## Examples
    ///
    /// ```
    /// use comms::gf::GF256;
    ///
    /// let element = GF256::new(0x53);
    /// ```
    #[inline]
    pub const fn new(value: u8) -> Self {
        return Self(value);
    }

    /// # Multiplies two elements in GF(2^8) using the standard polynomial basis.
    ///
    /// Implements multiplication using shift-and-add with reduction modulo the field polynomial.
    ///
    /// ## Arguments
    ///
    /// * `a` - First operand as a raw byte
    /// * `b` - Second operand as a raw byte
    ///
    /// ## Returns
    ///
    /// * The product in GF(2^8) as a raw byte
    ///
    /// ## Examples
    ///
    /// ```
    /// use comms::gf::GF256;
    ///
    /// let product = GF256::multiply(0x53, 0x0F);
    /// ```
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

    /// # Computes the multiplicative inverse of an element in GF(2^8).
    ///
    /// Uses Fermat's Little Theorem: a^254 is the multiplicative inverse of a in GF(2^8).
    /// Implements this efficiently using a square-and-multiply algorithm.
    ///
    /// ## Arguments
    ///
    /// * `a` - The element to invert as a raw byte
    ///
    /// ## Returns
    ///
    /// * The multiplicative inverse in GF(2^8) as a raw byte, or 0 if the input is 0
    ///
    /// ## Examples
    ///
    /// ```
    /// use comms::gf::GF256;
    ///
    /// let inverse = GF256::inverse(0x53);  // Computes multiplicative inverse of 0x53
    /// ```
    pub fn inverse(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }

        let mut result: u8 = a;
        for i in 0..7 {
            result = Self::multiply(result, result);

            if i != 6 {
                result = Self::multiply(result, a);
            }
        }

        return result;
    }

    /// # Divides two elements in GF(2^8).
    ///
    /// Division is implemented as multiplication by the multiplicative inverse.
    ///
    /// ## Arguments
    ///
    /// * `a` - Numerator as a raw byte
    /// * `b` - Denominator as a raw byte
    ///
    /// ## Returns
    ///
    /// * The quotient in GF(2^8) as a raw byte, or 0 if dividing by 0
    ///
    /// ## Examples
    ///
    /// ```
    /// use comms::gf::GF256;
    ///
    /// let quotient = GF256::divide(0x53, 0x0F);
    /// ```
    pub fn divide(a: u8, b: u8) -> u8 {
        if b == 0 {
            return 0;
        }

        return Self::multiply(a, Self::inverse(b));
    }
}

/// # Addition operator for GF256 elements.
///
/// In GF(2^8), addition is performed using bitwise XOR operations since we're working
/// in characteristic 2. This means a + a = 0 for all elements a.
///
/// ## Arguments
///
/// * `self` - First operand
/// * `rhs` - Second operand to add
///
/// ## Returns
///
/// * Sum of the two elements in GF(2^8)
impl core::ops::Add for GF256 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        return GF256(self.0 ^ rhs.0);
    }
}

/// # Subtraction operator for GF256 elements.
///
/// In GF(2^8), subtraction is identical to addition since we're working in
/// characteristic 2. This means a - a = 0 for all elements a, and it is
/// implemented using bitwise XOR operations.
///
/// ## Arguments
///
/// * `self` - First operand
/// * `rhs` - Second operand to subtract
///
/// ## Returns
///
/// * Difference of the two elements in GF(2^8)
impl core::ops::Sub for GF256 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        return GF256(self.0 ^ rhs.0);
    }
}

/// # Multiplication operator for GF256 elements.
///
/// Performs multiplication in GF(2^8) by calling into the low-level multiply() function.
/// The operation is performed modulo the field polynomial.
///
/// ## Arguments
///
/// * `self` - First operand
/// * `rhs` - Second operand to multiply
///
/// ## Returns
///
/// * Product of the two elements in GF(2^8)
impl core::ops::Mul for GF256 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        GF256(Self::multiply(self.0, rhs.0))
    }
}

/// # Division operator for GF256 elements.
///
/// Performs division in GF(2^8) by calling into the low-level divide() function.
/// Division is implemented as multiplication by the multiplicative inverse.
/// Returns 0 if dividing by 0.
///
/// ## Arguments
///
/// * `self` - Numerator (dividend)
/// * `rhs` - Denominator (divisor)
///
/// ## Returns
///
/// * Quotient of the two elements in GF(2^8)
impl core::ops::Div for GF256 {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self {
        return GF256(Self::divide(self.0, rhs.0));
    }
}
