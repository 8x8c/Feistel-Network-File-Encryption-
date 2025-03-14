
use clap::{Parser, Subcommand};
use std::fs;

/// Number of rounds in our Feistel network.
/// In practice, you'd want at least 16 rounds for any real encryption scheme.
const NUM_ROUNDS: usize = 8;

/// CLI definition using `clap`.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file path
        input: String,
        /// Output (encrypted) file path
        output: String,
        /// Password (used to derive subkeys)
        password: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file path
        input: String,
        /// Output (decrypted) file path
        output: String,
        /// Password (used to derive subkeys)
        password: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
        } => {
            // Read the input file as raw bytes
            let data = fs::read(&input).expect("Failed to read input file");

            // Encrypt using Feistel
            let encrypted = feistel_encrypt(&data, &password);

            // Write out the encrypted data
            fs::write(&output, &encrypted).expect("Failed to write encrypted file");
            println!("File encrypted successfully: {}", output);
        }
        Commands::Decrypt {
            input,
            output,
            password,
        } => {
            let data = fs::read(&input).expect("Failed to read input file");

            // Decrypt using Feistel
            let decrypted = feistel_decrypt(&data, &password);

            // Write out the decrypted data
            fs::write(&output, &decrypted).expect("Failed to write decrypted file");
            println!("File decrypted successfully: {}", output);
        }
    }
}

/// Feistel encryption of the entire data buffer.
/// This breaks the input into 8-byte blocks, applies Feistel rounds, and concatenates.
fn feistel_encrypt(data: &[u8], password: &str) -> Vec<u8> {
    let subkeys = generate_subkeys(password, NUM_ROUNDS);

    // Pad data to multiple of 8 bytes (64 bits).
    let mut padded_data = data.to_vec();
    while padded_data.len() % 8 != 0 {
        padded_data.push(0); // naive zero-padding
    }

    // Process each 8-byte block
    let mut output = Vec::with_capacity(padded_data.len());
    for chunk in padded_data.chunks(8) {
        let block = u64::from_le_bytes(chunk.try_into().unwrap());
        let encrypted_block = feistel_encrypt_block(block, &subkeys);
        output.extend_from_slice(&encrypted_block.to_le_bytes());
    }

    output
}

/// Feistel decryption of the entire data buffer.
/// Uses the same subkeys in **reverse** order.
fn feistel_decrypt(data: &[u8], password: &str) -> Vec<u8> {
    let subkeys = generate_subkeys(password, NUM_ROUNDS);

    // Process each 8-byte block
    let mut output = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        if chunk.len() < 8 {
            // Handle partial block as needed; for now, we break out.
            break;
        }
        let block = u64::from_le_bytes(chunk.try_into().unwrap());
        let decrypted_block = feistel_decrypt_block(block, &subkeys);
        output.extend_from_slice(&decrypted_block.to_le_bytes());
    }

    // Remove trailing zero padding. (Naive; use a proper padding scheme in real code.)
    while let Some(&last) = output.last() {
        if last == 0 {
            output.pop();
        } else {
            break;
        }
    }

    output
}

/// Encrypt a single 64-bit block with Feistel rounds.
fn feistel_encrypt_block(block: u64, subkeys: &[u32]) -> u64 {
    // Split 64-bit block into two 32-bit halves
    let mut left = (block & 0xFFFF_FFFF) as u32;
    let mut right = (block >> 32) as u32;

    // Perform the Feistel rounds
    for &k in subkeys {
        let new_left = right;
        let f_result = feistel_round_function(right, k);
        let new_right = left ^ f_result;

        left = new_left;
        right = new_right;
    }

    // Combine the halves into a single 64-bit block again
    // Note: Some Feistel designs swap final halves
    ((right as u64) << 32) | (left as u64)
}

/// Decrypt a single 64-bit block with Feistel rounds (reverse subkey order).
fn feistel_decrypt_block(block: u64, subkeys: &[u32]) -> u64 {
    let mut left = (block & 0xFFFF_FFFF) as u32;
    let mut right = (block >> 32) as u32;

    for &k in subkeys.iter().rev() {
        let new_right = left;
        let f_result = feistel_round_function(left, k);
        let new_left = right ^ f_result;

        left = new_left;
        right = new_right;
    }

    ((right as u64) << 32) | (left as u64)
}

/// Feistel round function F. (Simplistic example; real ciphers use S-boxes, etc.)
fn feistel_round_function(half_block: u32, subkey: u32) -> u32 {
    half_block.rotate_left(5).wrapping_add(subkey)
}

/// Generate Feistel subkeys from the provided password.
/// In real encryption, you'd use a proper KDF like PBKDF2, Argon2, etc.
fn generate_subkeys(password: &str, rounds: usize) -> Vec<u32> {
    // Very naive hash to produce `rounds` 32-bit subkeys (for demonstration only).
    let mut subkeys = Vec::with_capacity(rounds);
    let mut hash_val: u64 = 0x1234_5678_9ABC_DEF0;

    for (i, byte) in password.as_bytes().iter().enumerate() {
        hash_val = hash_val
            .wrapping_mul(0x100_000_001_B3)
            .wrapping_add(*byte as u64 + i as u64);
    }

    for i in 0..rounds {
        let part = (hash_val.rotate_left(i as u32) & 0xFFFF_FFFF) as u32;
        subkeys.push(part ^ (i as u32));
        hash_val = hash_val.wrapping_add(part as u64).rotate_right(3);
    }

    subkeys
}

