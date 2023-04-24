//! A module containing padding modes.

use rand::random;


#[derive(Clone, Copy, Debug, PartialEq)]
/// The enum with padding types.
pub enum PaddingTypes {
    /// PKCS#7 padding. The value of each added byte is the total number of bytes that need to be added. This padding scheme is defined in RFC 2315.
    PKCS7,
    /// ISO 7816-4 padding. The first byte of the padding is 0x80. All other bytes of the padding are 0x00. This padding scheme is defined in ISO/IEC 7816-4.
    ISO78164,
    /// ISO/IEC 10126-2 padding. The last byte of the padding (thus, the last byte of the block) is the number of pad bytes. All other bytes of the padding are some random data. This padding scheme is defined in ISO/IEC 10126-2.
    ISO101262,
    /// ANSI X9.23 padding. The last byte of the padding (thus, the last byte of the block) is the number of pad bytes. All other bytes of the padding are zeros. This padding scheme is defined in ANSI X9.23.
    X923,
    /// For use with certain cipher modes which don't require padding.
    None,
}

#[derive(Debug)]
#[allow(dead_code)]
/// The padding struct.
pub struct Padding {
    /// The padding type.
    pub padding_type: PaddingTypes,
    /// unused field to prevent struct initialization
    private: (),
}

impl Padding {
    pub fn new(padding_type: PaddingTypes) -> Self {
        //! Creates a new padding struct.
        //! # Arguments
        //! * `padding_type` - The padding type, see the `PaddingTypes` enum.

        Self {
            padding_type,
            private: (),
        }
    }

    pub fn pad(&self, input: &[u8]) -> [u8; 16] {
        //! Pads the input to 16 bytes.
        //! # Arguments
        //! * `input` - The input to be padded. Should be less than 16 bytes long. Zero length input is allowed.
        //! # Panics
        //! * Panics if the padding type is `PaddingTypes::None`.
        //! * Panics if the input is 16 bytes long.

        if self.padding_type == PaddingTypes::None {
            panic!("Trying to pad with None padding type.")
        }

        if input.len() == 16 {
            panic!("Trying to pad 16 bytes long input.")
        }

        let mut output: [u8; 16] = [0; 16];
        output[..input.len()].copy_from_slice(input);

        match self.padding_type {
            PaddingTypes::PKCS7 => {
                output[input.len()..16].fill((16 - input.len()) as u8);
            }
            PaddingTypes::ISO78164 => {
                output[input.len()] = 0x80;
                output[(input.len() + 1)..16].fill(0);
            }
            PaddingTypes::ISO101262 => {
                output[output.len() - 1] = (16 - input.len()) as u8;
                for i in input.len()..(output.len() - 1) {
                    output[i] = random::<u8>();
                }
            }
            PaddingTypes::X923 => {
                output[15] = (16 - input.len()) as u8;
                output[input.len()..15].fill(0);
            }
            _ => {panic!("This should not be possible to reach.")}
        }

        output
    }

    pub fn de_pad<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        //! Removes the padding from the input.
        //! # Arguments
        //! * `input` - The input to be de-padded. Should be 16 bytes long.
        //! # Panics
        //! * Panics if the padding type is `PaddingTypes::None`.
        //! * Panics if the padding is invalid.

        if self.padding_type == PaddingTypes::None {
            panic!("Trying to de-pad with None padding type.")
        }

        #[allow(clippy::needless_range_loop)]
        let upper_bound = match self.padding_type {
            PaddingTypes::PKCS7 => {
                let padding_length = input[input.len() - 1];

                if padding_length > 16 || padding_length as usize > input.len() {
                    panic!("Invalid padding.");
                }

                for i in (input.len() - padding_length as usize)..(input.len() - 1) {
                    if input[i] != padding_length {
                        panic!("Invalid padding.");
                    }
                }

                input.len() - padding_length as usize
            }
            PaddingTypes::ISO78164 => {
                let mut curr_index: usize = input.len() - 1;

                while input[curr_index] == 0 {
                    curr_index -= 1;
                }

                if input[curr_index] != 0x80 || input.len() - curr_index > 16{
                    panic!("Invalid padding.");
                }

                curr_index
            }
            PaddingTypes::ISO101262 => {
                let padding_length: usize = input[input.len() - 1] as usize;
                if padding_length > 16 || padding_length > input.len() {
                    panic!("Invalid padding.");
                }

                input.len() - padding_length
            }
            PaddingTypes::X923 => {
                let padding_length = input[input.len() - 1] as usize;
                if padding_length > 16 {
                    panic!("Invalid padding.");
                }

                for i in (input.len() - padding_length)..(input.len() - 1) {
                    if input[i] != 0 {
                        panic!("Invalid padding.");
                    }
                }

                input.len() - padding_length
            }
            _ => {panic!("This should not be possible to reach.")}
        };

        &input[..upper_bound]
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding() {
        //! Tests the PKCS#7 padding.

        let padding: Padding = Padding::new(PaddingTypes::PKCS7);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1);
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2);
        let wanted2: [u8; 16] = [0x10; 16];
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3);
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn pkcs7_de_padding() {
        //! Tests the PKCS#7 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::PKCS7);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        let output1: &[u8] = padding.de_pad(&input1);
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let input2: [u8; 16] = [0x10; 16];
        let output2: &[u8] = padding.de_pad(&input2);
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        let output3: &[u8] = padding.de_pad(&input3);
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn iso78164_padding() {
        //! Tests the ISO 7816-4 padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO78164);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1);
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2);
        let wanted2: [u8; 16] = [0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3);
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b10000000];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn iso78164_de_padding() {
        //! Tests the ISO 7816-4 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO78164);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let output1: &[u8] = padding.de_pad(&input1);
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let input2: [u8; 16] = [0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let output2: &[u8] = padding.de_pad(&input2);
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b10000000];
        let output3: &[u8] = padding.de_pad(&input3);
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn iso101262_padding() {
        //! Tests the ISO 10126-2 padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO101262);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1);
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        assert_eq!(output1[0..2], wanted1[0..2]);
        assert_eq!(output1[15], wanted1[15]);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2);
        let wanted2: [u8; 16] = [0x10; 16];
        assert_eq!(output2[0..0], wanted2[0..0]);
        assert_eq!(output2[15], wanted2[15]);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3);
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        assert_eq!(output3[0..15], wanted3[0..15]);
        assert_eq!(output3[15], wanted3[15]);
    }

    #[test]
    fn iso101262_de_padding() {
        //! Tests the ISO 10126-2 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO101262);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0xff, 0xcc, 0xaa, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        let output1: &[u8] = padding.de_pad(&input1);
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let input2: [u8; 16] = [0x10; 16];
        let output2: &[u8] = padding.de_pad(&input2);
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        let output3: &[u8] = padding.de_pad(&input3);
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn x923_padding() {
        //! Tests the ANSI X9.23 padding.

        let padding: Padding = Padding::new(PaddingTypes::X923);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1);
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2);
        let mut wanted2: [u8; 16] = [0; 16];
        wanted2[15] = 0x10;
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3);
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn x923_de_padding() {
        //! Tests the ANSI X9.23 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::X923);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
        let output1: &[u8] = padding.de_pad(&input1);
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let mut input2: [u8; 16] = [0; 16];
        input2[15] = 0x10;
        let output2: &[u8] = padding.de_pad(&input2);
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        let output3: &[u8] = padding.de_pad(&input3);
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    #[should_panic]
    fn none_padding() {
        //! Tests the None padding. Should panic because it is not possible to pad with None.

        let padding = Padding::new(PaddingTypes::None);
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let _output = padding.pad(&input);
    }

    #[test]
    #[should_panic]
    fn none_de_padding() {
        //! Tests the None de-padding. Should panic because it is not possible to de-pad with None.

        let padding = Padding::new(PaddingTypes::None);
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let _output = padding.de_pad(&input);
    }
}
