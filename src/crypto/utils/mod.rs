pub mod u256;

use self::u256::U256;

pub fn bytes_to_word(byte_array: &[u8]) -> u32 {
    let mut return_value: u32 = 0;
    for i in (0..4).rev() {
        return_value = (return_value << 8) | (byte_array[i] as u32);
    }
    return return_value;
}

pub fn word_to_bytes(word: u32) -> [u8; 4] {
    [
        (word & 255) as u8,
        ((word >> 8) & 255) as u8,
        ((word >> 16) & 255) as u8,
        ((word >> 24) & 255) as u8
    ]
}