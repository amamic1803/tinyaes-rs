enum PaddingTypes {
    None,
    PKCS7,
    ISO10126,
    X923,
    Zero,
}

struct Padding {
    padding_type: PaddingTypes,
    return_value: [u8; 16],
}

impl Padding {
    fn new() -> Padding {
        Padding {
            padding_type: PaddingTypes::None,
            return_value: [0; 16],
        }
    }
}