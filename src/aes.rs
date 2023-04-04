//! A module containing the AES algorithm.


#[derive(Debug)]
/// The AES key used to encrypt and decrypt data.
pub enum AESKey {
    AES128([u8; 16]),
    AES192([u8; 24]),
    AES256([u8; 32]),
}


#[derive(Debug)]
/// The AES algorithm.
pub struct AES {
    /// The AES key used to encrypt and decrypt data.
    pub key: AESKey,
    /// The round keys used in the AES algorithm.
    pub(crate) round_keys: Vec<[u8; 4]>,
}


/// Public functions for encrypting and decrypting data.
impl AES {
    pub fn new(key: AESKey) -> AES {
        //! Creates a new AES instance with the given key.

        let round_keys: Vec<[u8; 4]> = Self::key_expansion(&key);

        Self {
            key,
            round_keys,
        }
    }

    pub fn encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        //! Encrypts the given block of data.

        // convert block to state
        let mut state: [[u8; 4]; 4] = [[0; 4]; 4];
        for r in 0..4 {
            for c in 0..4 {
                state[r][c] = block[r + c * 4];
            }
        }

        // encryption starts here
        Self::add_round_key(&mut state, &self.round_keys[0..4]);
        for round in 1..(match self.key {
            AESKey::AES128(_) => 10,
            AESKey::AES192(_) => 12,
            AESKey::AES256(_) => 14,
        }) {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[(self.round_keys.len() - 4)..]);
        // encryption ends here

        // convert state to output block
        let mut out_block: [u8; 16] = [0; 16];
        for r in 0..4 {
            for c in 0..4 {
                out_block[r + c * 4] = state[r][c];
            }
        }
        out_block
    }

    pub fn decrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        //! Decrypts the given block of data.

        // convert block to state
        let mut state: [[u8; 4]; 4] = [[0; 4]; 4];
        for r in 0..4 {
            for c in 0..4 {
                state[r][c] = block[r + c * 4];
            }
        }

        // decryption starts here
        Self::add_round_key(&mut state, &self.round_keys[(self.round_keys.len() - 4)..]);
        for round in (1..(match self.key {
            AESKey::AES128(_) => 10,
            AESKey::AES192(_) => 12,
            AESKey::AES256(_) => 14,
        })).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
            Self::inv_mix_columns(&mut state);
        }
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[0..4]);
        // decryption ends here

        // convert state to output block
        let mut out_block: [u8; 16] = [0; 16];
        for r in 0..4 {
            for c in 0..4 {
                out_block[r + c * 4] = state[r][c];
            }
        }
        out_block
    }
}

/// Functions for encrypting and decrypting used in the AES algorithm.
impl AES {
    pub(crate) fn add_round_key(state: &mut [[u8; 4]; 4], round_keys: &[[u8; 4]]) {
        //! Adds the given round key to the state.

        for r in 0..4 {
            for c in 0..4 {
                state[r][c] ^= round_keys[c][r];
            }
        }
    }

    pub(crate) fn mix_columns(state: &mut [[u8; 4]; 4]) {
        //! Mixes the columns of the state.

        let mut temp_column: [u8; 4] = [0; 4];
        for c in 0..4 {
            temp_column[0] =
                (if (state[0][c] >> 7) == 1 {(state[0][c] << 1) ^ 0x1b} else {state[0][c] << 1}) ^
                ((if (state[1][c] >> 7) == 1 {(state[1][c] << 1) ^ 0x1b} else {state[1][c] << 1}) ^ state[1][c]) ^
                state[2][c] ^
                state[3][c];

            temp_column[1] =
                state[0][c] ^
                (if (state[1][c] >> 7) == 1 {(state[1][c] << 1) ^ 0x1b} else {state[1][c] << 1}) ^
                ((if (state[2][c] >> 7) == 1 {(state[2][c] << 1) ^ 0x1b} else {state[2][c] << 1}) ^ state[2][c]) ^
                state[3][c];

            temp_column[2] =
                state[0][c] ^
                state[1][c] ^
                (if (state[2][c] >> 7) == 1 {(state[2][c] << 1) ^ 0x1b} else {state[2][c] << 1}) ^
                ((if (state[3][c] >> 7) == 1 {(state[3][c] << 1) ^ 0x1b} else {state[3][c] << 1}) ^ state[3][c]);


            temp_column[3] =
                ((if (state[0][c] >> 7) == 1 {(state[0][c] << 1) ^ 0x1b} else {state[0][c] << 1}) ^ state[0][c]) ^
                state[1][c] ^
                state[2][c] ^
                (if (state[3][c] >> 7) == 1 {(state[3][c] << 1) ^ 0x1b} else {state[3][c] << 1});

            state[0][c] = temp_column[0];
            state[1][c] = temp_column[1];
            state[2][c] = temp_column[2];
            state[3][c] = temp_column[3];
        }
    }

    pub(crate) fn shift_rows(state: &mut [[u8; 4]; 4]) {
        //! Shifts the rows of the state.

        state[1].rotate_left(1);
        state[2].rotate_left(2);
        state[3].rotate_left(3);
    }

    pub(crate) fn sub_bytes(state: &mut [[u8; 4]; 4]) {
        //! Substitutes the bytes of the state with the S-Box.

        for r in 0..4 {
            for c in 0..4 {
                state[r][c] = S_BOX[(state[r][c] >> 4) as usize][(state[r][c] & 0b00001111) as usize];
            }
        }
    }

    pub(crate) fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
        //! Inverse mixes the columns of the state.
        
        let mut temp_column: [u8; 4] = [0; 4];
        let mut temp_mul: [[u8; 3]; 4] = [[0; 3]; 4];

        for c in 0..4 {
            for i in 0..4 {
                temp_mul[i][0] = if (state[i][c] >> 7) == 1 {(state[i][c] << 1) ^ 0x1b} else {state[i][c] << 1};
            }
            for i in 0..4 {
                for j in 1..3 {
                    temp_mul[i][j] = if (temp_mul[i][j - 1] >> 7) == 1 {
                        (temp_mul[i][j - 1] << 1) ^ 0x1b
                    } else {
                        temp_mul[i][j - 1] << 1
                    };
                }
            }

            // 09 = 01 + 08
            // 0b = 01 + 02 + 08
            // 0d = 01 + 04 + 08
            // 0e = 02 + 04 + 08
            // temp_mul = [[02, 04, 08]]

            temp_column[0] = 
                (temp_mul[0][0] ^ temp_mul[0][1] ^ temp_mul[0][2]) ^
                (state[1][c] ^ temp_mul[1][0] ^ temp_mul[1][2]) ^
                (state[2][c] ^ temp_mul[2][1] ^ temp_mul[2][2]) ^
                (state[3][c] ^ temp_mul[3][2]);

            temp_column[1] =
                (state[0][c] ^ temp_mul[0][2]) ^
                (temp_mul[1][0] ^ temp_mul[1][1] ^ temp_mul[1][2]) ^
                (state[2][c] ^ temp_mul[2][0] ^ temp_mul[2][2]) ^
                (state[3][c] ^ temp_mul[3][1] ^ temp_mul[3][2]);
            
            temp_column[2] =
                (state[0][c] ^ temp_mul[0][1] ^ temp_mul[0][2]) ^
                (state[1][c] ^ temp_mul[1][2]) ^
                (temp_mul[2][0] ^ temp_mul[2][1] ^ temp_mul[2][2]) ^
                (state[3][c] ^ temp_mul[3][0] ^ temp_mul[3][2]);
            
            temp_column[3] =
                (state[0][c] ^ temp_mul[0][0] ^ temp_mul[0][2]) ^
                (state[1][c] ^ temp_mul[1][1] ^ temp_mul[1][2]) ^
                (state[2][c] ^ temp_mul[2][2]) ^
                (temp_mul[3][0] ^ temp_mul[3][1] ^ temp_mul[3][2]);

            state[0][c] = temp_column[0];
            state[1][c] = temp_column[1];
            state[2][c] = temp_column[2];
            state[3][c] = temp_column[3];
        }
    }

    pub(crate) fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
        //! Inverse shifts the rows of the state.

        state[1].rotate_right(1);
        state[2].rotate_right(2);
        state[3].rotate_right(3);
    }

    pub(crate) fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
        //! Inverse substitutes the bytes of the state with the inverse S-Box.

        for r in 0..4 {
            for c in 0..4 {
                state[r][c] = INV_S_BOX[(state[r][c] >> 4) as usize][(state[r][c] & 0b00001111) as usize];
            }
        }
    }
}

/// Key expansion functions for the AES algorithm.
impl AES {
    pub(crate) fn key_expansion(key: &AESKey) -> Vec<[u8; 4]> {
        //! Expands the key into a vector of round keys.

        let num_of_words: usize = 4 * (1 + match key {
            AESKey::AES128(_) => 10,
            AESKey::AES192(_) => 12,
            AESKey::AES256(_) => 14,
        });

        let mut round_keys: Vec<[u8; 4]> = Vec::with_capacity(num_of_words);
        match key {
            AESKey::AES128(key_seq) => {
                for i in (0..16).step_by(4) {
                    round_keys.push([key_seq[i], key_seq[i + 1], key_seq[i + 2], key_seq[i + 3]]);
                }
            },
            AESKey::AES192(key_seq) => {
                for i in (0..24).step_by(4) {
                    round_keys.push([key_seq[i], key_seq[i + 1], key_seq[i + 2], key_seq[i + 3]]);
                }
            },
            AESKey::AES256(key_seq) => {
                for i in (0..32).step_by(4) {
                    round_keys.push([key_seq[i], key_seq[i + 1], key_seq[i + 2], key_seq[i + 3]]);
                }
            },
        }

        let nk: usize = match key {
            AESKey::AES128(_) => 4,
            AESKey::AES192(_) => 6,
            AESKey::AES256(_) => 8,
        };

        for i in round_keys.len()..num_of_words {
            let mut temp: [u8; 4] = round_keys[i - 1];
            if i % nk == 0 {
                Self::rot_word(&mut temp);
                Self::sub_word(&mut temp);
                temp[0] ^= (R_CON[(i / nk) - 1] >> 24) as u8;
            } else if nk == 8 && i % nk == 4 {
                Self::sub_word(&mut temp);
            }
            round_keys.push([
                round_keys[i - nk][0] ^ temp[0],
                round_keys[i - nk][1] ^ temp[1],
                round_keys[i - nk][2] ^ temp[2],
                round_keys[i - nk][3] ^ temp[3],
            ]);
        }

        round_keys
    }

    pub(crate) fn rot_word(word: &mut [u8; 4]) {
        //! Rotates the word to the left by one byte.

        word.rotate_left(1);
    }

    pub(crate) fn sub_word(word: &mut [u8; 4]) {
        //! Substitutes the bytes of the word with the S-Box.

        for i in 0..4 {
            word[i] = S_BOX[(word[i] >> 4) as usize][(word[i] & 0b00001111) as usize];
        }
    }
}


/// The S-Box used in the AES algorithm.
pub const S_BOX: [[u8; 16]; 16] = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];

/// The inverse S-Box used in the AES algorithm.
pub const INV_S_BOX: [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
];

/// The round constants used in the AES algorithm.
pub const R_CON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
];
