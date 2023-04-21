//! **tinyaes** is a pure Rust implementation of the Advanced Encryption Standard (AES).
//!
//! It supports AES-128, AES-192, and AES-256.
//! This is a low-level implementation, and is currently only able to encrypt blocks of data.
//! As of now, it is not intended to be used directly, but rather as a building block for other cryptographic libraries.
//! Higher-level functions may be added in the future.
//!
//! **Example:** Encrypting a block of data with AES-256
//! ```
//! use tinyaes::AESCore;
//! use tinyaes::AESKey;
//!
//! let key: [u8; 32] = "This is a 256-bit key as bytes!!".as_bytes().try_into().unwrap();
//! let plaintext: [u8; 16] = "This is a block!".as_bytes().try_into().unwrap();
//!
//! let aes256: AESCore = AESCore::new(AESKey::AES256(key));
//! let ciphertext: [u8; 16] = aes256.encrypt(&plaintext);
//!
//! let expected_result: [u8; 16] = [0x08, 0x39, 0x58, 0x3b, 0xc4, 0x15, 0xef, 0xf6, 0x7e, 0x46, 0x65, 0x04, 0x03, 0x7e, 0x7a, 0x88];
//! assert_eq!(ciphertext, expected_result);
//!
//! let decrypted: [u8; 16] = aes256.decrypt(&ciphertext);
//! assert_eq!(decrypted, plaintext);
//! ```


pub mod aes_core;
mod parallelism;
mod padding;

#[doc(inline)]
pub use aes_core::*;
