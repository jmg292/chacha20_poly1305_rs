mod crypto;
use crate::crypto::poly1305::Poly1305;
use crate::crypto::chacha20::ChaCha20;

use std::vec::Vec;

pub struct Chacha20Poly1305 {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl Chacha20Poly1305 {
    pub fn aead_encrypt(self, aad: Vec<u8>, plaintext: Vec<u8>) -> (Vec<u8>, [u8; 16]) {
        let mut poly_1305 = Poly1305::new();
        let mut cipher = ChaCha20::new(self.key, self.nonce);
        let mut mac_data: Vec<u8> = Vec::new();
        let mut mac_key: [u8; 32] = [0; 32];
        let cipher_state = cipher.chacha_block();
        for i in 0..32 {
            mac_key[i] = cipher_state[i];
        }
        let ciphertext = cipher.encrypt_stream(plaintext);
        for value in aad.iter() {
            mac_data.push(*value);
        }
        mac_data.append(&mut Self::pad_16(aad.len()));
        for value in ciphertext.iter() {
            mac_data.push(*value);
        }
        mac_data.append(&mut Self::pad_16(ciphertext.len()));
        for value in (aad.len() as u64).to_le_bytes().iter() {
            mac_data.push(*value);
        }
        for value in (ciphertext.len() as u64).to_le_bytes().iter() {
            mac_data.push(*value);
        }
        (ciphertext, poly_1305.mac(mac_data, mac_key))
    }

    pub fn aead_decrypt(self, aad: Vec<u8>, ciphertext: Vec<u8>, tag: [u8; 16]) -> (Vec<u8>, bool) {
        let mut poly1305 = Poly1305::new();
        let mut cipher = ChaCha20::new(self.key, self.nonce);
        let mut mac_data: Vec<u8> = Vec::new();
        let mut mac_key: [u8; 32] = [0; 32];
        let cipher_state = cipher.chacha_block();
        for i in 0..32 {
            mac_key[i] = cipher_state[i];
        }
        for value in aad.iter() {
            mac_data.push(*value);
        }
        mac_data.append(&mut Self::pad_16(aad.len()));
        for value in ciphertext.iter() {
            mac_data.push(*value);
        }
        mac_data.append(&mut Self::pad_16(ciphertext.len()));
        for value in (aad.len() as u64).to_le_bytes().iter() {
            mac_data.push(*value);
        }
        for value in (ciphertext.len() as u64).to_le_bytes().iter() {
            mac_data.push(*value);
        }
        let tag_2 = poly1305.mac(mac_data, mac_key);
        if Self::tags_match(tag, tag_2) {
            return (cipher.encrypt_stream(ciphertext), true);
        }
        (Vec::new(), false)
    }

    fn tags_match(first_tag: [u8; 16], second_tag: [u8; 16]) -> bool {
        let mut difference: u128 = 0;
        for i in 0..16 {
            difference += (first_tag[i] ^ second_tag[i]) as u128;
        }
        difference == 0
    }

    fn pad_16(length: usize) -> Vec<u8> {
        let mut return_value: Vec<u8> = Vec::new();
        while (length + return_value.len()) % 16 != 0 {
            return_value.push(0x0);
        }
        return return_value;
    }

    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Chacha20Poly1305 {
        Chacha20Poly1305 {
            key: key,
            nonce: nonce,
        }
    }
}


pub fn main() {
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    ];
    let nonce: [u8; 12] = [
       0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 
       0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    ];
    let msg: [u8; 114] = [
       0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
       0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
       0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
       0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
       0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
       0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
       0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
       0x74, 0x2e   
    ];
    let aad: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    ];
    let (ciphertext, tag) = Chacha20Poly1305::new(key, nonce).aead_encrypt(aad.to_vec(), msg.to_vec());
    println!("{}\n----", ciphertext.iter().fold(String::new(), |acc, &x| acc + &format!("{:02x} ", &x)));
    println!("{}\n----", tag.iter().fold(String::new(), |acc, &x| acc + &format!("{:02x} ", &x)));
    let (plaintext, matched) = Chacha20Poly1305::new(key, nonce).aead_decrypt(aad.to_vec(), ciphertext, tag);
    if matched {
        println!("{}", plaintext.iter().fold(String::new(), |acc, &x| acc + &format!("{:02x} ", &x)));
    } else {
        println!("Tag mismatch.");
    }
}
