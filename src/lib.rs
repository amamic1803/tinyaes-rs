pub mod aes;
#[doc(inline)]
pub use aes::*;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        let key = AESKey::AES256([0; 32]);
        let aes = AES::new(key);
        let mut block: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        block = aes.encrypt(block);
        println!("{:?}", block);
    }

    #[test]
    fn key_expansion() {
        //! Test the key expansion function

        let aes128: AES = AES::new(AESKey::AES128(
            [0x2b, 0x7e, 0x15, 0x16,
             0x28, 0xae, 0xd2, 0xa6,
             0xab, 0xf7, 0x15, 0x88,
             0x09, 0xcf, 0x4f, 0x3c],
        ));

        let aes192: AES = AES::new(AESKey::AES192(
            [0x8e, 0x73, 0xb0, 0xf7,
             0xda, 0x0e, 0x64, 0x52,
             0xc8, 0x10, 0xf3, 0x2b,
             0x80, 0x90, 0x79, 0xe5,
             0x62, 0xf8, 0xea, 0xd2,
             0x52, 0x2c, 0x6b, 0x7b],
        ));

        let aes256: AES = AES::new(AESKey::AES256(
            [0x60, 0x3d, 0xeb, 0x10,
             0x15, 0xca, 0x71, 0xbe,
             0x2b, 0x73, 0xae, 0xf0,
             0x85, 0x7d, 0x77, 0x81,
             0x1f, 0x35, 0x2c, 0x07,
             0x3b, 0x61, 0x08, 0xd7,
             0x2d, 0x98, 0x10, 0xa3,
             0x09, 0x14, 0xdf, 0xf4],
        ));

        assert_eq!(aes128.round_keys[aes128.round_keys.len() - 1], [0xb6, 0x63, 0x0c, 0xa6]);
        assert_eq!(aes128.round_keys.len(), 44);
        assert_eq!(aes192.round_keys[aes192.round_keys.len() - 1], [0x01, 0x00, 0x22, 0x02]);
        assert_eq!(aes192.round_keys.len(), 52);
        assert_eq!(aes256.round_keys[aes256.round_keys.len() - 1], [0x70, 0x6c, 0x63, 0x1e]);
        assert_eq!(aes256.round_keys.len(), 60);
    }
}
