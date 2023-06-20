//! A module containing padding modes.





// DISABLED LINTS

#![allow(clippy::needless_range_loop)]  // better readability





// ENUMS

/// The enum with padding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaddingError {
    /// The padding is invalid and cannot be removed.
    InvalidPadding,
    /// The input to be padded is 16 or more bytes long.
    /// Should be less than 16 bytes long.
    InvalidSize,
    /// The padded input isn't 16 bytes long.
    InvalidPaddedSize,
    /// Trying to pad/de-pad with `PaddingTypes::None`.
    NonePadding,
}

/// The enum with padding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaddingTypes {
    /// PKCS#7 padding.
    /// The value of each added byte is the total number of bytes that need to be added.
    /// This padding scheme is defined in RFC 2315.
    PKCS7,
    /// ISO 7816-4 padding.
    /// The first byte of the padding is 0x80.
    /// All other bytes of the padding are 0x00.
    /// This padding scheme is defined in ISO/IEC 7816-4.
    ISO78164,
    /// ANSI X9.23 padding.
    /// The last byte of the padding (thus, the last byte of the block) is the number of pad bytes.
    /// All other bytes of the padding are zeros.
    /// This padding scheme is defined in ANSI X9.23.
    X923,
    /// Don't use padding.
    /// For use with certain cipher modes which don't require padding.
    None,
}





// STRUCTS

/// The padding struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Padding {
    /// The padding type.
    padding_type: PaddingTypes,
}

/// The public functions for the padding struct.
impl Padding {
    pub fn new(padding_type: PaddingTypes) -> Self {
        //! Creates a new padding struct.
        //! # Arguments
        //! * `padding_type` - The padding type, see the `PaddingTypes` enum.

        Self {
            padding_type,
        }
    }

    pub fn padding_type(&self) -> PaddingTypes {
        //! Returns the padding type.
        //! # Returns
        //! * PaddingTypes - The padding type, see the `PaddingTypes` enum.

        self.padding_type
    }

    pub fn set_padding_type(&mut self, padding_type: PaddingTypes) {
        //! Sets the padding type.
        //! # Arguments
        //! * `padding_type` - The padding type, see the `PaddingTypes` enum.

        self.padding_type = padding_type;
    }

    pub fn pad(&self, input: &[u8]) -> Result<[u8; 16], PaddingError> {
        //! Pads the input to 16 bytes.
        //! # Arguments
        //! * `input` - The input to be padded. Should be less than 16 bytes long. Zero length input is allowed.
        //! # Returns
        //! * Result<[u8; 16], PaddingError> - The padded input or an error.
        //! # Errors
        //! * PaddingError::InvalidSize - The input is 16 or more bytes long.
        //! * PaddingError::NonePadding - Trying to pad with `PaddingTypes::None`.

        if self.padding_type == PaddingTypes::None {
            return Err(PaddingError::NonePadding);
        }

        if input.len() >= 16 {
            return Err(PaddingError::InvalidSize);
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
            PaddingTypes::X923 => {
                output[15] = (16 - input.len()) as u8;
                output[input.len()..15].fill(0);
            }
            PaddingTypes::None => panic!("This should not be possible to reach."),
        }

        Ok(output)
    }

    pub fn de_pad<'a>(&self, input: &'a [u8]) -> Result<&'a [u8], PaddingError> {
        //! Removes the padding from the input.
        //! # Arguments
        //! * `input` - The input to be de-padded. Should be 16 bytes long.
        //! # Returns
        //! * Result<&[u8], PaddingError> - The de-padded input or an error.
        //! # Errors
        //! * PaddingError::InvalidPadding - The padding is invalid and cannot be removed.
        //! * PaddingError::InvalidPaddedSize - The input isn't 16 bytes long.
        //! * PaddingError::NonePadding - Trying to de-pad with `PaddingTypes::None`.

        if self.padding_type == PaddingTypes::None {
            return Err(PaddingError::NonePadding);
        }

        if input.len() != 16 {
            return Err(PaddingError::InvalidPaddedSize);
        }

        let upper_bound = match self.padding_type {
            PaddingTypes::PKCS7 => {
                let padding_length = input[input.len() - 1];

                if padding_length > 16 || padding_length as usize > input.len() {
                    return Err(PaddingError::InvalidPadding);
                }

                for i in (input.len() - padding_length as usize)..(input.len() - 1) {
                    if input[i] != padding_length {
                        return Err(PaddingError::InvalidPadding);
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
                    return Err(PaddingError::InvalidPadding);
                }

                curr_index
            }
            PaddingTypes::X923 => {
                let padding_length = input[input.len() - 1] as usize;
                if padding_length > 16 {
                    return Err(PaddingError::InvalidPadding);
                }

                for i in (input.len() - padding_length)..(input.len() - 1) {
                    if input[i] != 0 {
                        return Err(PaddingError::InvalidPadding);
                    }
                }

                input.len() - padding_length
            }
            PaddingTypes::None => panic!("This should not be possible to reach."),
        };

        Ok(&input[..upper_bound])
    }
}





// TESTS

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        let padding = Padding::new(PaddingTypes::PKCS7);

        assert_eq!(padding.padding_type, PaddingTypes::PKCS7);
    }

    #[test]
    fn set_padding_type() {
        let mut padding = Padding::new(PaddingTypes::X923);

        assert_eq!(padding.padding_type, PaddingTypes::X923);
        assert_eq!(padding.padding_type(), PaddingTypes::X923);

        padding.set_padding_type(PaddingTypes::PKCS7);

        assert_eq!(padding.padding_type, PaddingTypes::PKCS7);
        assert_eq!(padding.padding_type(), PaddingTypes::PKCS7);
    }

    #[test]
    fn pkcs7_padding() {
        //! Tests the PKCS#7 padding.

        let padding: Padding = Padding::new(PaddingTypes::PKCS7);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1).unwrap();
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2).unwrap();
        let wanted2: [u8; 16] = [0x10; 16];
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3).unwrap();
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn pkcs7_de_padding() {
        //! Tests the PKCS#7 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::PKCS7);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e];
        let output1: &[u8] = padding.de_pad(&input1).unwrap();
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let input2: [u8; 16] = [0x10; 16];
        let output2: &[u8] = padding.de_pad(&input2).unwrap();
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        let output3: &[u8] = padding.de_pad(&input3).unwrap();
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn iso78164_padding() {
        //! Tests the ISO 7816-4 padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO78164);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1).unwrap();
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2).unwrap();
        let wanted2: [u8; 16] = [0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3).unwrap();
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b10000000];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn iso78164_de_padding() {
        //! Tests the ISO 7816-4 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::ISO78164);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let output1: &[u8] = padding.de_pad(&input1).unwrap();
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let input2: [u8; 16] = [0b10000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let output2: &[u8] = padding.de_pad(&input2).unwrap();
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b10000000];
        let output3: &[u8] = padding.de_pad(&input3).unwrap();
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn x923_padding() {
        //! Tests the ANSI X9.23 padding.

        let padding: Padding = Padding::new(PaddingTypes::X923);

        let input1: [u8; 2] = [0b10100001, 0b10100000];
        let output1: [u8; 16] = padding.pad(&input1).unwrap();
        let wanted1: [u8; 16] = [0b10100001, 0b10100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
        assert_eq!(output1, wanted1);

        let input2: [u8; 0] = [];
        let output2: [u8; 16] = padding.pad(&input2).unwrap();
        let mut wanted2: [u8; 16] = [0; 16];
        wanted2[15] = 0x10;
        assert_eq!(output2, wanted2);

        let input3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let output3: [u8; 16] = padding.pad(&input3).unwrap();
        let wanted3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn x923_de_padding() {
        //! Tests the ANSI X9.23 de-padding.

        let padding: Padding = Padding::new(PaddingTypes::X923);

        let input1: [u8; 16] = [0b10100001, 0b10100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
        let output1: &[u8] = padding.de_pad(&input1).unwrap();
        let wanted1: [u8; 2] = [0b10100001, 0b10100000];
        assert_eq!(output1, wanted1);

        let mut input2: [u8; 16] = [0; 16];
        input2[15] = 0x10;
        let output2: &[u8] = padding.de_pad(&input2).unwrap();
        let wanted2: [u8; 0] = [];
        assert_eq!(output2, wanted2);

        let input3: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0b00000001];
        let output3: &[u8] = padding.de_pad(&input3).unwrap();
        let wanted3: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert_eq!(output3, wanted3);
    }

    #[test]
    fn padding_errors() {
        let padding_type = PaddingTypes::PKCS7;
        let input = [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
        ];
        let mut padded_input = [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            0x04, 0x04, 0x04, 0x04,
        ];
        let padding = Padding::new(padding_type);

        assert_eq!(padding.pad(&input).unwrap(), padded_input);
        assert_eq!(padding.pad(&[0; 16]), Err(PaddingError::InvalidSize));
        assert_eq!(padding.pad(&[0; 17]), Err(PaddingError::InvalidSize));

        assert_eq!(padding.de_pad(&padded_input).unwrap(), input);
        assert_eq!(padding.de_pad(&[0; 15]), Err(PaddingError::InvalidPaddedSize));
        assert_eq!(padding.de_pad(&[0; 17]), Err(PaddingError::InvalidPaddedSize));

        padded_input[15] = 0x05;
        assert_eq!(padding.de_pad(&padded_input), Err(PaddingError::InvalidPadding));

        let new_padding = Padding::new(PaddingTypes::None);
        assert_eq!(new_padding.pad(&input), Err(PaddingError::NonePadding));
        assert_eq!(new_padding.de_pad(&padded_input), Err(PaddingError::NonePadding));
    }
}
