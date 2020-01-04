use crate::crypto::utils;

use std::vec::Vec;


pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    block_count: u32,
    current_state: [u32; 16],
    modulus: u64
}

impl ChaCha20 {

    fn create_state(key: [u8; 32], nonce: [u8; 12], block_count: u32) -> [u32; 16] {
        let mut new_state: [u32; 16] = [
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
            0, 0, 0, 0,
            0, 0, 0, 0,
            block_count,
            utils::bytes_to_word(&nonce[0..4]),
            utils::bytes_to_word(&nonce[4..8]),
            utils::bytes_to_word(&nonce[8..12])
        ];
        for i in 0..8 {
            let index = i * 4;
            new_state[4 + i] = utils::bytes_to_word(&key[index..index + 4]);
        }
        return new_state;
    }

    fn update_state(&self, mut working_state: [u32; 16], a: usize, b: usize, c: usize, d: usize) -> [u32; 16] {
        let updated_points: [usize; 4] = [a, b, c, d];
        let updated_set = self.quarter_round(working_state[a], working_state[b], working_state[c], working_state[d]);
        for i in 0..4 {
            working_state[updated_points[i]] = updated_set[i];
        }
        return working_state;
    }

    fn quarter_round(&self, mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> [u32; 4] {
        a = ((a as u64 + b as u64) % self.modulus) as u32;
        d = (d ^ a).rotate_left(16);
        c = ((c as u64 + d as u64) % self.modulus) as u32;
        b = (b ^ c).rotate_left(12);
        a = ((a as u64 + b as u64) % self.modulus) as u32;
        d = (d ^ a).rotate_left(8);
        c = ((c as u64 + d as u64) % self.modulus) as u32;
        b = (b ^ c).rotate_left(7);
        [a, b, c, d]
    }

    pub fn chacha_block(&mut self) -> [u8; 64] {
        self.current_state = Self::create_state(self.key, self.nonce, self.block_count);
        let mut working_state = self.current_state;
        let mut keystream: [u8; 64] = [0; 64];
        for _ in 0..10 {
            // Horizontal round
            working_state = self.update_state(working_state, 0, 4, 8, 12);
            working_state = self.update_state(working_state, 1, 5, 9, 13);
            working_state = self.update_state(working_state, 2, 6, 10, 14);
            working_state = self.update_state(working_state, 3, 7, 11, 15);
            // Diagonal round
            working_state = self.update_state(working_state, 0, 5, 10, 15);
            working_state = self.update_state(working_state, 1, 6, 11, 12);
            working_state = self.update_state(working_state, 2, 7, 8, 13);
            working_state = self.update_state(working_state, 3, 4, 9, 14);
        }
        for i in 0..16 {
            let state_value = ((self.current_state[i] as u64 + working_state[i] as u64) % self.modulus) as u32;
            self.current_state[i] = state_value;
        }
        for i in 0..16 {
            let keystream_value = self.current_state[i].to_le_bytes();
            let keystream_index = i * 4;
            for n in 0..4 {
                keystream[keystream_index + n] = keystream_value[n];
            }
        }
        self.block_count += 1;
        return keystream;
    }

    pub fn encrypt_stream(&mut self, plaintext: Vec<u8>) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut keystream: [u8; 64] = [0; 64];
        for i in 0..plaintext.len() {
            if i % 64 == 0 {
                keystream = self.chacha_block();
            }
            ciphertext.push(plaintext[i] ^ keystream[i % 64]);
        }
        return ciphertext;
    }

    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> ChaCha20 {
        ChaCha20{
            key: key,
            nonce: nonce,
            block_count: 0,
            current_state: ChaCha20::create_state(key, nonce, 0),
            modulus: (2 as u64).pow(32)
        }
    }
}