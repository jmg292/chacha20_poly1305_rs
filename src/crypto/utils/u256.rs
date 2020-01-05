use core::convert::{From, Into};
use core::ops::{Add, Sub, Not, Mul, Div, Rem, Shr, Shl, BitAnd, BitOr, BitXor};
use core::cmp::Ordering;

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct U256([u8; 32]);

impl U256 {
    pub fn to_hex_string(self) -> String {
        let U256(ref arr) = self;
        arr.iter().fold(String::new(), |acc, &x| acc + &format!("{:02x}", &x))
    }

    pub fn from_hex_string(value: &str) -> U256 {
        let mut value_array: [u8; 32] = [0; 32];
        let formatted_value = &format!("{:0>64}", value);
        for i in (0..formatted_value.len()).step_by(2) {
            value_array[i / 2] = u8::from_str_radix(&formatted_value[i..i+2], 16).unwrap();
        }
        U256(value_array)
    }

    pub fn to_byte_array(self) -> [u8; 32] {
        let U256(ref arr) = self;
        return *arr;
    }

    pub fn from_16_byte_array(value: [u8; 16]) -> U256 {
        let mut value_array: [u8; 32] = [0; 32];
        for i in 0..16 {
            value_array[i + 16] = value[i];
        }
        U256(value_array)
    }

    pub fn from_message_block(message_block: std::vec::Drain<'_, u8>) -> U256 {
        let mut index: usize = 31;
        let mut byte_array: [u8; 32] = [0; 32];
        for value in message_block {
            byte_array[index] = value;
            index -= 1;
        }
        byte_array[index] = 0x01;
        U256(byte_array)
    }

    pub fn zero() -> U256 {
        U256([0; 32])
    }

    pub fn one() -> U256 {
        U256([
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1
        ])
    }

    pub fn max() -> U256 {
        U256([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ])
    }
}

impl From<u32> for U256 {
    fn from(val: u32) -> U256 {
        let mut value_array: [u8; 32] = [0; 32];
        let value_bytes = val.to_be_bytes();
        for i in 0..4 {
            value_array[i + 28] = value_bytes[i];
        }
        U256(value_array)
    }
}

impl From<u8> for U256 {
    fn from(val: u8) -> U256 {
        U256([
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, val
        ])
    }
}

impl Into<u8> for U256 {
    fn into(self) -> u8 {
        for b in &self.0[0..31] {
            assert_eq!(*b, 0);
        }
        self.0[31]
    }
}

impl From<usize> for U256 {
    fn from(val: usize) -> U256 {
        let mut value_array: [u8; 32] = [0; 32];
        let value_bytes = val.to_be_bytes();
        let offset = value_array.len() - value_bytes.len();
        for (i, &v) in value_bytes.iter().enumerate() {
            value_array[i + offset] = v;
        }
        U256(value_array)
    }
}

impl Into<usize> for U256 {
    fn into(self) -> usize {
        let mut value_bytes = 0usize.to_be_bytes();
        let offset = 32 - value_bytes.len();
        for b in &self.0[0..offset] {
            assert_eq!(*b, 0);
        }
        for (i, v) in value_bytes.iter_mut().enumerate() {
            *v = self.0[i + offset];
        }
        usize::from_be_bytes(value_bytes)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &U256) -> Ordering {
        let &U256(ref first) = self;
        let &U256(ref second) = other;
        for i in 0..32 {
            if first[i] < second[i] {
                return Ordering::Less;
            }
            if first[i] > second[i] {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &U256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl BitAnd for U256 {
    type Output = Self;
    fn bitand(self, value: U256) -> Self::Output {
        let mut result_array: [u8; 32] = [0; 32];
        let U256(ref target) = self;
        let U256(ref source) = value;
        for i in 0..32 {
            result_array[i] = source[i] & target[i];
        }
        U256(result_array)
    }
}

impl BitOr for U256 {
    type Output = Self;
    fn bitor(self, value: U256) -> Self::Output {
        let mut result_array: [u8; 32] = [0; 32];
        let U256(ref target) = self;
        let U256(ref source) = value;
        for i in 0..32 {
            result_array[i] = source[i] | target[i];
        }
        U256(result_array)
    }
}

impl BitXor for U256 {
    type Output = Self;
    fn bitxor(self, value: U256) -> Self::Output {
        let mut result_array: [u8; 32] = [0; 32];
        let U256(ref target) = self;
        let U256(ref source) = value;
        for i in 0..32 {
            result_array[i] = source[i] ^ target[i];
        }
        U256(result_array)
    }
}

impl Shl for U256 {
    type Output = Self;
    fn shl(self, value: U256) -> Self::Output {
        let U256(ref source) = self;
        let mut result_array: [u8; 32] = [0; 32];
        for i in 0..32 {
            result_array[i] = source[i];
        }
        let shift_count: u8 = value.into();
        for _ in 0..shift_count {
            for i in 0..32 {
                let carry_flag: bool = (result_array[i] & 0x80) > 0;
                if carry_flag && i > 0 {
                    result_array[i - 1] |= 0x01;
                }
                result_array[i] = result_array[i] << 0x01;
            }
        }
        U256(result_array)
    }
}

impl Shr for U256 {
    type Output = Self;
    fn shr(self, value: U256) -> Self::Output {
        let U256(ref source) = self;
        let mut result_array: [u8; 32] = [0; 32];
        for i in 0..32 {
            result_array[i] = source[i];
        }
        let shift_count: u8 = value.into();
        for _ in 0..shift_count {
            for i in (0..32).rev() {
                let carry_flag: bool = (result_array[i] & 0x01) > 0;
                if carry_flag && i < 31 {
                    result_array[i + 1] |= 0x80;
                }
                result_array[i] = result_array[i] >> 0x01;
            }
        }
        U256(result_array)
    }
}

impl Not for U256 {
    type Output = Self;
    fn not(self) -> U256 {
        self ^ U256::max()
    }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, value: U256) -> Self::Output {
        let mut a = self;
        let mut b = value;
        let mut sum = U256::zero();
        let mut carry = U256::one();
        while carry != U256::zero() {
            sum = a ^ b;
            carry = (a & b) << U256::one();
            a = sum;
            b = carry;
        }
        return sum;
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, value: U256) -> Self::Output {
        self + (!value + U256::one())
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, value: U256) -> Self::Output {
        let mut target = value;
        let mut counter = U256::zero();
        let mut accumulator = U256::zero();
        while target > U256::zero() {
            if target & U256::one() == U256::one() {
                accumulator = accumulator + (self << counter);
            }
            counter = counter + U256::one();
            target = target >> U256::one();
        }
        return accumulator;
    }
}

impl Div for U256 {
    type Output = Self;
    fn div(self, divisor: U256) -> Self::Output {
        if self == divisor {
            return U256::one();
        } else if self < divisor {
            return U256::zero();
        }
        let mut dividend = self;
        let mut quotient = U256::zero();
        for i in (0..256).rev() {
            let shift = U256::from(i as usize);
            let r = divisor << shift;
            if r <= dividend {
                quotient = quotient | (U256::one() << shift);
                dividend = dividend - r;
            }
        }
        return quotient;
    }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, divisor: U256) -> Self::Output {
        if self < divisor {
            return self;
        }
        self - (divisor * (self / divisor))
    }
}
