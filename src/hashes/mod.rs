use std::vec::Vec;

pub struct SHA3 {
    input_bytes: Vec<u8>,
    current_state: [[u64; 5]; 5],
    block_size: u64,
    digest_size: u64,
    n_r: u64,
    c: u64
}

impl SHA3 {

    const OFFSET: [[u8; 5]; 5] = [
        [0,  36,   3,  41,  18],
        [1,  44,  10,  45,   2],
        [62,  6,  43,  15,  61],
        [28, 55,  25,  21,  56],
        [27, 20,  39,   8,  14]
    ];

    const ROUND_CONSTANTS: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008
    ];

    fn keccak_round(a: [[u64; 5]; 5], round_constant: u64) -> [[u64; 5]; 5] {

        let mut state: [[u64; 5]; 5] = a;
        let mut b: [[u64; 5]; 5] = [[0; 5]; 5];
        let mut c: [u64; 5] = [0; 5];
        let mut d: [u64; 5] = [0; 5];

        for i in 0..5 {
            c[i] = state[i].iter().fold(0, |acc, x| acc ^ x);
        }

        for i in 0..5 {
            d[i] = c[((i as i32) - 1).rem_euclid(5) as usize] ^ c[(i + 1) % 5].rotate_left(1);
        }

        for i in 0..5 {
            for n in 0..5 {
                state[i][n] ^= d[i];
            }
        }

        for i in 0..5 {
            for n in 0..5 {
                b[n][(2 * i + 3 * n) % 5] = state[i][n].rotate_left(SHA3::OFFSET[i][n] as u32);
            }
        }

        for i in 0..5 {
            for n in 0..5 {
                state[i][n] = b[i][n] ^ ((!b[(i + 1) % 5][n]) & b[(i + 2) % 5][n]);
            }
        }

        state[0][0] ^= round_constant;
        return state;
    }

    fn keccak_function(&mut self) {
        for i in 0..self.n_r {
            let index = i as usize;
            self.current_state = Self::keccak_round(self.current_state, Self::ROUND_CONSTANTS[index]);
        }
    }

    fn pad_vector(&mut self) {
        let b = self.block_size + self.c;
        let padding_bytes_required = ((self.input_bytes.len() as i64) * -1).rem_euclid((b / 8) as i64);
        if padding_bytes_required > 1 {
            self.input_bytes.push(0x80);
            while (((self.input_bytes.len() as i64) * -1).rem_euclid((b / 8) as i64)) > 1 {
                self.input_bytes.push(0x00);
            }
            self.input_bytes.push(0x01);
        } else if padding_bytes_required == 1 {
            self.input_bytes.push(0x81);
        }
    }

    fn absorb_vector(&mut self) -> [[u64; 5]; 5] {
        let mut absorbed_state: [[u64; 5]; 5] = [[0; 5]; 5];
        for i in 0..5 {
            for n in 0..5 {
                let state_value = self.input_bytes.drain(0..8).fold(0, |acc, x| (acc << 8) | (x as u64));
                absorbed_state[i][n] = state_value;
            }
        }
        self.input_bytes.shrink_to_fit();
        return absorbed_state;
    }

    fn update_state(&mut self) {
        let b = (self.block_size + self.c) / 8;
        while self.input_bytes.len() as u64 >= b {
            let absorbed_state = self.absorb_vector();
            for i in 0..5 {
                for n in 0..5 {
                    self.current_state[i][n] ^= absorbed_state[i][n];
                }
            }
        }
    }

    pub fn update_with_bytes(&mut self, input_bytes: &[u8]) {
        self.input_bytes.append(&mut input_bytes.to_vec());
        self.update_state();
    }

    pub fn update(&mut self, input_str: &str) {
        self.update_with_bytes(input_str.as_bytes());
    }

    pub fn digest(&mut self) -> Vec<u8> {

        self.pad_vector();
        self.update_state();

        let mut digest_output: Vec<u8> = Vec::new();
        let digest_byte_size = (self.digest_size / 8) as usize;

        while digest_output.len() < digest_byte_size {
            self.keccak_function();
            for i in 0..5 {
                for n in 0..5 {
                    let state_value = self.current_state[i][n];
                    for x in (0..4).rev() {
                        digest_output.push(((state_value >> (x * 8)) & 255) as u8);
                    }
                }
            }
        }
        digest_output.truncate(digest_byte_size);
        return digest_output;
    }

    pub fn hex_digest(&mut self) -> String {
        return self.digest().iter().map(|b| format!("{:02x}", b)).collect();
    }

    pub fn sha_256(input_str: &str) -> SHA3 {
        SHA3::new(
            input_str,
            1088,
            512,
            256
        )
    }

    pub fn sha_512(input_str: &str) -> SHA3 {
        SHA3::new(
            input_str,
            576,
            1024,
            512
        )
    }

    fn new(input_str: &str, r: u64, c: u64, n: u64) -> SHA3 {
        let n_r  = 12 + 2 * (((r as f64 + c as f64) / 25.0).log2().floor() as u64);
        SHA3 {
            input_bytes: input_str.as_bytes().to_vec(),
            current_state: [[0; 5]; 5],
            block_size: r,
            digest_size: n,
            n_r: n_r,
            c: c
        }
    }
}