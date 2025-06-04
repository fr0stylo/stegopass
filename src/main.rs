use std::io::{self, Write};
use std::{error::Error, fmt, path::PathBuf};
use std::{thread, time::Duration};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use clap::{Parser, Subcommand};
use image::{DynamicImage, RgbImage};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use rpassword;
use sha2::{Digest, Sha256};

// Constants for magic numbers
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const LENGTH_PREFIX_SIZE: usize = 2;
const CHANNELS_PER_PIXEL: usize = 3;
const BITS_PER_BYTE: usize = 8;

/// Custom error types for better error handling
#[derive(Debug)]
pub enum StegoError {
    Io(std::io::Error),
    Image(image::ImageError),
    Crypto(aes_gcm::Error),
    InvalidData(String),
    InsufficientCapacity(String),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for StegoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::Image(err) => write!(f, "Image error: {err}"),
            Self::Crypto(err) => write!(f, "Cryptographic error: {err}"),
            Self::InvalidData(msg) => write!(f, "Invalid data: {msg}"),
            Self::InsufficientCapacity(msg) => write!(f, "Insufficient capacity: {msg}"),
            Self::Utf8(err) => write!(f, "UTF-8 error: {err}"),
        }
    }
}

impl Error for StegoError {}

impl From<std::io::Error> for StegoError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<image::ImageError> for StegoError {
    fn from(err: image::ImageError) -> Self {
        Self::Image(err)
    }
}

impl From<aes_gcm::Error> for StegoError {
    fn from(err: aes_gcm::Error) -> Self {
        Self::Crypto(err)
    }
}

impl From<std::string::FromUtf8Error> for StegoError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8(err)
    }
}

type Result<T> = std::result::Result<T, StegoError>;

#[derive(Parser)]
#[command(name = "stegopass")]
#[command(about = "Hide/retrieve encrypted passwords in images", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hide an encrypted password in an image
    Hide {
        /// Input image path
        #[arg(short, long)]
        input: PathBuf,
        /// Output image path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Extract an encrypted password from an image
    Extract {
        /// Input image path containing hidden data
        #[arg(short, long)]
        input: PathBuf,
    },
}

/// Represents a pixel coordinate and channel
#[derive(Debug, Clone, Copy)]
struct PixelPosition {
    x: u32,
    y: u32,
    channel: usize,
}

/// Handles steganographic operations
struct SteganographyEngine {
    rng: StdRng,
}

impl SteganographyEngine {
    /// Creates a new engine with RNG seeded from passphrase
    fn new(passphrase: &str) -> Self {
        let hash = Sha256::digest(passphrase.as_bytes());
        let seed: [u8; 32] = hash[..32]
            .try_into()
            .expect("SHA256 hash is always 32 bytes");

        Self {
            rng: StdRng::from_seed(seed),
        }
    }

    /// Generates randomized pixel positions for embedding data
    fn get_pixel_positions(
        &mut self,
        width: u32,
        height: u32,
        num_bits: usize,
    ) -> Result<Vec<PixelPosition>> {
        let total_channels = (width * height * CHANNELS_PER_PIXEL as u32) as usize;

        if num_bits > total_channels {
            return Err(StegoError::InsufficientCapacity(format!(
                "Need {} bits but only {} channels available",
                num_bits, total_channels
            )));
        }

        let mut indices: Vec<usize> = (0..total_channels).collect();
        indices.shuffle(&mut self.rng);
        indices.truncate(num_bits);

        Ok(indices
            .into_iter()
            .map(|i| {
                let pixel_idx = i / CHANNELS_PER_PIXEL;
                let channel = i % CHANNELS_PER_PIXEL;
                let x = (pixel_idx as u32) % width;
                let y = (pixel_idx as u32) / width;
                PixelPosition { x, y, channel }
            })
            .collect())
    }

    /// Embeds data into an image using LSB steganography
    fn embed_data(&mut self, img: &DynamicImage, data: &[u8]) -> Result<RgbImage> {
        let mut img = img.to_rgb8();
        let (width, height) = img.dimensions();

        let bits = data
            .iter()
            .flat_map(|&byte| (0..BITS_PER_BYTE).rev().map(move |i| (byte >> i) & 1))
            .collect::<Vec<_>>();

        let positions = self.get_pixel_positions(width, height, bits.len())?;

        for (bit, position) in bits.into_iter().zip(positions) {
            let pixel = img.get_pixel_mut(position.x, position.y);
            pixel.0[position.channel] = (pixel.0[position.channel] & 0xFE) | bit;
        }

        Ok(img)
    }

    /// Extracts data from an image using LSB steganography
    fn extract_data(&mut self, img: &DynamicImage, num_bytes: usize) -> Result<Vec<u8>> {
        let img = img.to_rgb8();
        let (width, height) = img.dimensions();
        let num_bits = num_bytes * BITS_PER_BYTE;

        let positions = self.get_pixel_positions(width, height, num_bits)?;

        let bits: Vec<u8> = positions
            .into_iter()
            .map(|position| {
                let pixel = img.get_pixel(position.x, position.y);
                pixel.0[position.channel] & 1
            })
            .collect();

        Ok(bits
            .chunks(BITS_PER_BYTE)
            .map(|chunk| chunk.iter().fold(0, |acc, &bit| (acc << 1) | bit))
            .collect())
    }
}

/// Handles cryptographic operations
struct CryptoEngine;

impl CryptoEngine {
    /// Derives a key from passphrase using Argon2
    fn derive_key(passphrase: &str, salt: &[u8; SALT_SIZE]) -> [u8; KEY_SIZE] {
        let argon2 = Argon2::default();
        let mut key = [0u8; KEY_SIZE];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .expect("Argon2 key derivation should not fail");
        key
    }

    /// Encrypts password with passphrase
    fn encrypt_password(
        password: &str,
        passphrase: &str,
    ) -> Result<(Vec<u8>, [u8; NONCE_SIZE], [u8; SALT_SIZE])> {
        let salt: [u8; SALT_SIZE] = rand::random();
        let key = Self::derive_key(passphrase, &salt);
        let nonce: [u8; NONCE_SIZE] = rand::random();

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| StegoError::InvalidData("Invalid key size".to_string()))?;

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), password.as_bytes())?;

        Ok((ciphertext, nonce, salt))
    }

    /// Decrypts password with passphrase
    fn decrypt_password(
        ciphertext: &[u8],
        passphrase: &str,
        nonce: &[u8; NONCE_SIZE],
        salt: &[u8; SALT_SIZE],
    ) -> Result<String> {
        let key = Self::derive_key(passphrase, salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| StegoError::InvalidData("Invalid key size".to_string()))?;

        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
        Ok(String::from_utf8(plaintext)?)
    }
}

/// Represents the payload structure for steganography
#[derive(Debug)]
struct SteganographyPayload {
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
}

impl SteganographyPayload {
    /// Creates a new payload from encrypted data
    fn new(salt: [u8; SALT_SIZE], nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self {
            salt,
            nonce,
            ciphertext,
        }
    }

    /// Serializes payload to bytes (matches original format)
    fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u16;
        let mut payload =
            Vec::with_capacity(SALT_SIZE + NONCE_SIZE + LENGTH_PREFIX_SIZE + self.ciphertext.len());

        // Build inner payload: salt + nonce + ct_len + ciphertext
        payload.extend_from_slice(&self.salt);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&ct_len.to_be_bytes());
        payload.extend_from_slice(&self.ciphertext);

        // Add payload length prefix
        let payload_len = payload.len() as u16;
        let mut stego_payload = Vec::with_capacity(LENGTH_PREFIX_SIZE + payload.len());
        stego_payload.extend_from_slice(&payload_len.to_be_bytes());
        stego_payload.extend(payload);

        // Add total length prefix (matches original structure)
        let total_len = stego_payload.len() as u16;
        let mut final_payload = Vec::with_capacity(LENGTH_PREFIX_SIZE + stego_payload.len());
        final_payload.extend_from_slice(&total_len.to_be_bytes());
        final_payload.extend(stego_payload);

        final_payload
    }

    /// Deserializes payload from bytes (matches original parsing logic)
    fn from_bytes(data: &[u8]) -> Result<Self> {
        // Skip first length prefix to get to stego_payload
        if data.len() < LENGTH_PREFIX_SIZE {
            return Err(StegoError::InvalidData(
                "Data too short for length prefix".to_string(),
            ));
        }

        let stego_payload = &data[LENGTH_PREFIX_SIZE..];

        // Skip second length prefix to get to actual payload
        if stego_payload.len() < LENGTH_PREFIX_SIZE {
            return Err(StegoError::InvalidData(
                "Stego payload too short".to_string(),
            ));
        }

        let len_prefix = &stego_payload[..LENGTH_PREFIX_SIZE];
        let payload_len = u16::from_be_bytes([len_prefix[0], len_prefix[1]]) as usize;
        let payload = &stego_payload[LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + payload_len];

        // Parse payload: salt (16) + nonce (12) + ct_len (2) + ciphertext
        if payload.len() < SALT_SIZE + NONCE_SIZE + LENGTH_PREFIX_SIZE {
            return Err(StegoError::InvalidData(
                "Payload too short for required fields".to_string(),
            ));
        }

        let (salt_bytes, rest) = payload.split_at(SALT_SIZE);
        let (nonce_bytes, rest) = rest.split_at(NONCE_SIZE);
        let (ct_len_bytes, ct_data) = rest.split_at(LENGTH_PREFIX_SIZE);

        let ct_len = u16::from_be_bytes([ct_len_bytes[0], ct_len_bytes[1]]) as usize;

        if ct_data.len() < ct_len {
            return Err(StegoError::InvalidData(format!(
                "Insufficient ciphertext data: expected {}, got {}",
                ct_len,
                ct_data.len()
            )));
        }

        let salt: [u8; SALT_SIZE] = salt_bytes
            .try_into()
            .map_err(|_| StegoError::InvalidData("Invalid salt size".to_string()))?;

        let nonce: [u8; NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| StegoError::InvalidData("Invalid nonce size".to_string()))?;

        let ciphertext = ct_data[..ct_len].to_vec();

        Ok(Self::new(salt, nonce, ciphertext))
    }
}

/// Handles the hide operation
fn hide_password(
    input_path: &PathBuf,
    output_path: &PathBuf,
    password: &str,
    passphrase: &str,
) -> Result<()> {
    let img = image::open(input_path)?;
    let (ciphertext, nonce, salt) = CryptoEngine::encrypt_password(password, passphrase)?;

    let payload = SteganographyPayload::new(salt, nonce, ciphertext);
    let payload_bytes = payload.to_bytes();

    let mut stego_engine = SteganographyEngine::new(passphrase);
    let stego_image = stego_engine.embed_data(&img, &payload_bytes)?;

    stego_image.save(output_path)?;
    println!("Password hidden successfully in {}", output_path.display());

    Ok(())
}

/// Handles the extract operation
fn extract_password(input_path: &PathBuf, passphrase: &str, print: bool) -> Result<()> {
    let img = image::open(input_path)?;

    // First extract the length prefix (2 bytes) - create fresh engine
    let mut stego_engine = SteganographyEngine::new(passphrase);
    let len_prefix = stego_engine.extract_data(&img, 2)?;
    let total_bytes_to_extract = u16::from_be_bytes([len_prefix[0], len_prefix[1]]) as usize;

    // Now extract the full payload (length prefix + payload) - create fresh engine again
    let mut stego_engine = SteganographyEngine::new(passphrase);
    let final_stego_payload = stego_engine.extract_data(&img, 2 + total_bytes_to_extract)?;
    let stego_payload = &final_stego_payload[2..];

    let len_prefix = &stego_payload[..2];
    let payload_len = u16::from_be_bytes([len_prefix[0], len_prefix[1]]) as usize;
    let payload = &stego_payload[2..2 + payload_len];

    // Parse payload: salt (16), nonce (12), ct_len (2), ct (ct_len) - matches original exactly
    let (salt, rest) = payload.split_at(16);
    let (nonce, rest) = rest.split_at(12);
    let (ct_len_bytes, ct_and_rest) = rest.split_at(2);
    let ct_len = u16::from_be_bytes([ct_len_bytes[0], ct_len_bytes[1]]) as usize;
    let (ct, _extra) = ct_and_rest.split_at(ct_len);

    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| StegoError::InvalidData("Invalid salt size".to_string()))?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| StegoError::InvalidData("Invalid nonce size".to_string()))?;

    let password = CryptoEngine::decrypt_password(ct, passphrase, &nonce, &salt)?;
    let mut clipboard = arboard::Clipboard::new().unwrap();
    clipboard.set_text(password.clone()).unwrap();
    println!("Extracted password copied to clipboard!");
    if print {
        println!("Extracted password: {}", password);
    } else {
        // Temporary clipboard: show countdown, then clear clipboard
        let seconds = 1;
        for _i in (1..=seconds).rev() {
            io::stdout().flush().ok();
            thread::sleep(Duration::from_secs(1));
        }
        clipboard.set_text("").unwrap();
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hide { input, output } => {
            // Prompt for password interactively (hidden input)
            let password = rpassword::prompt_password("Enter data: ")?;
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            hide_password(&input, &output, password.trim(), passphrase.trim())
        }

        Commands::Extract { input } => {
            let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
            // Check for STEGOPASS_PRINT environment variable or CLI flag
            let print = std::env::var("STEGOPASS_PRINT").is_ok()
                || std::env::args().any(|arg| arg == "--print");
            extract_password(&input, passphrase.trim(), print)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_roundtrip() {
        let password = "test_password";
        let passphrase = "test_passphrase";

        let (ciphertext, nonce, salt) =
            CryptoEngine::encrypt_password(password, passphrase).unwrap();
        let decrypted =
            CryptoEngine::decrypt_password(&ciphertext, passphrase, &nonce, &salt).unwrap();

        assert_eq!(password, decrypted);
    }

    #[test]
    fn test_payload_serialization() {
        let salt = [1u8; SALT_SIZE];
        let nonce = [2u8; NONCE_SIZE];
        let ciphertext = vec![3u8; 10];

        let payload = SteganographyPayload::new(salt, nonce, ciphertext.clone());
        let bytes = payload.to_bytes();
        let reconstructed = SteganographyPayload::from_bytes(&bytes).unwrap();

        // The full payload should round-trip
        assert_eq!(payload.salt, reconstructed.salt);
        assert_eq!(payload.nonce, reconstructed.nonce);
        assert_eq!(payload.ciphertext, reconstructed.ciphertext);

        // The serialization should be reversible for the full structure
        let re_bytes = reconstructed.to_bytes();
        assert_eq!(bytes, re_bytes);
    }

    #[test]
    fn test_steganography_capacity_check() {
        let mut engine = SteganographyEngine::new("test");
        let result = engine.get_pixel_positions(10, 10, 1000); // Too many bits for 10x10 image
        assert!(result.is_err());
    }
}
