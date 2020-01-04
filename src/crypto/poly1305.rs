use crate::crypto::utils::u256::U256;

pub struct Poly1305 {
    prime: U256,
    accumulator: U256
}

impl Poly1305 {
    fn clamp(mut value: [u8; 16]) -> [u8; 16] {
        let odd_numbers: [usize; 4] = [3, 7, 11, 15];
        let even_numbers: [usize; 3] = [4, 8, 12];
        for i in odd_numbers.iter() {
            value[*i] &= 15;
        }
        for i in even_numbers.iter() {
            value[*i] &= 252;
        }
        return value;
    }

    pub fn mac(&mut self, mut msg: Vec<u8>, key: [u8; 32]) -> [u8; 16] {
        let mut return_value: [u8; 16] = [0; 16];
        let mut key_upper_bytes: [u8; 16] = [0; 16];
        let mut key_lower_bytes: [u8; 16] = [0; 16];
        for i in 0..32 {
            if i < 16 {
                key_upper_bytes[i] = key[i];
            } else {
                key_lower_bytes[i % 16] = key[i];
            }
        }
        let clamped_key = U256::from_16_byte_array(u128::from_le_bytes(Self::clamp(key_upper_bytes)).to_be_bytes());
        let s = U256::from_16_byte_array(u128::from_le_bytes(key_lower_bytes).to_be_bytes());
        while msg.len() > 0 {
            let msg_block_value: U256;
            if msg.len() >= 16 {
                msg_block_value = U256::from_message_block(msg.drain(0..16));
            } else {
                msg_block_value = U256::from_message_block(msg.drain(0..(msg.len())));
            }
            self.accumulator = self.accumulator + msg_block_value;
            self.accumulator = (clamped_key * self.accumulator) % self.prime;
        }
        self.accumulator = self.accumulator + s;
        let accumulator_bytes = self.accumulator.to_byte_array();
        for i in 0..16 {
            return_value[i] = accumulator_bytes[31 - i];
        }
        return return_value;
    }

    pub fn new() -> Poly1305 {
        Poly1305 {
            prime: U256::from_hex_string("03fffffffffffffffffffffffffffffffb"),
            accumulator: U256::zero(),
        }
    }
}