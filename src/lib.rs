pub mod aes;
#[doc(inline)]
pub use aes::*;


#[cfg(test)]
mod tests {
    use super::*;

    fn run_test_1() {
        let mut array_1: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut array_4: &mut [[u8; 4]; 4] = unsafe {
            *((&mut &mut array_1 as *mut &mut [u8; 16]) as *mut &mut [[u8; 4]; 4])
        };

        let tet: &mut [[u8; 4]; 4] = unsafe {
            std::mem::transmute::<&mut [u8; 16], &mut [[u8; 4]; 4]>(&mut array_1)
        };

        test_2(tet);

        array_1[0] = 0;
        tet[0][0] = 2;

        println!("{:?}", array_1);
        println!("{:?}", array_4);
        println!("{:?}", array_4[0][1] + array_4[3][2]);
        println!("{:?}", tet);
    }

    fn test_2(arr: &mut [[u8; 4]; 4]) {
        arr[0][2] = 22;
    }

    #[test]
    fn test_main() {
        let key = AESKey::AES256([0; 32]);
        let aes = AES::new(key);
        let mut block: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        block = aes.encrypt(block);
        println!("{:?}", block);

        println!("{:#?}", S_BOX);
    }
}

