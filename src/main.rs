use num_bigint::{BigInt, RandBigInt};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use std::time::{SystemTime, UNIX_EPOCH};
use bincode;
use serde::{Deserialize, Serialize};

// Define a large prime modulus for our field
const PRIME_MODULUS: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639319";
lazy_static::lazy_static! {
    static ref PRIME: BigInt = PRIME_MODULUS.parse().unwrap();
}

// Alias for AES-256 CTR encryption
type Aes256Ctr = ctr::Ctr64BE<Aes256>;

/// Structure representing a single share
#[derive(Serialize, Deserialize, Clone)]
pub struct Share {
    pub x: BigInt,
    pub y: BigInt,
    pub commitment: Vec<u8>,
    pub timestamp: u64,
}

/// ThresholdSecretSharing struct with parameters for threshold and total shares
pub struct ThresholdSecretSharing {
    threshold: usize,
    total_shares: usize,
}

impl ThresholdSecretSharing {
    /// Initialize a new threshold secret sharing instance
    pub fn new(threshold: usize, total_shares: usize) -> Self {
        assert!(threshold <= total_shares, "Threshold must be <= total shares.");
        ThresholdSecretSharing {
            threshold,
            total_shares,
        }
    }

    /// Split the secret into shares with commitments and timestamps
    pub fn split_secret(&self, secret: &BigInt) -> Vec<Share> {
        let mut rng = OsRng;
        let mut coefficients = vec![secret.clone() % &*PRIME]; // Constant term as secret
        for _ in 1..self.threshold {
            coefficients.push(rng.gen_bigint(256) % &*PRIME); // Random coefficients
        }

        (1..=self.total_shares)
            .map(|x| {
                let x_val = BigInt::from(x);
                let y_val = evaluate_polynomial(&coefficients, &x_val);
                let timestamp = current_timestamp();
                let share = Share { x: x_val.clone(), y: y_val.clone(), commitment: vec![], timestamp };
                let commitment = generate_commitment(&share);
                Share { x: x_val.clone(), y: y_val.clone(), commitment, timestamp }
            })
            .collect()
    }

    /// Reconstruct the secret from a subset of shares
    pub fn reconstruct_secret(&self, shares: &[Share]) -> BigInt {
        assert!(shares.len() >= self.threshold, "Insufficient shares to reconstruct the secret.");

        let mut secret = BigInt::from(0);

        for i in 0..shares.len() {
            let mut num = BigInt::from(1);
            let mut denom = BigInt::from(1);

            for j in 0..shares.len() {
                if i != j {
                    num = (num * &shares[j].x) % &*PRIME;
                    denom = (denom * (&shares[j].x - &shares[i].x)) % &*PRIME;
                }
            }

            let denom_inv = denom.modinv(&*PRIME).unwrap();
            let lagrange_coeff = (num * denom_inv) % &*PRIME;
            secret = (secret + (&shares[i].y * lagrange_coeff)) % &*PRIME;
        }

        secret
    }
}

/// Generate hash commitment for a share
fn generate_commitment(share: &Share) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // Only take the byte representation (Vec<u8>) of `to_bytes_be()` output
    hasher.update(share.x.to_bytes_be().1);
    hasher.update(share.y.to_bytes_be().1);
    hasher.finalize().to_vec()
}

/// Evaluate polynomial at given x value with modular arithmetic
fn evaluate_polynomial(coefficients: &[BigInt], x: &BigInt) -> BigInt {
    coefficients.iter().rev().fold(BigInt::from(0), |acc, coeff| {
        (acc * x + coeff) % &*PRIME
    })
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Share methods for verifying commitment, checking expiration, and encryption/decryption
impl Share {
    /// Verify if the commitment of the share is valid
    pub fn verify_commitment(&self) -> bool {
        let computed_commitment = generate_commitment(self);
        computed_commitment == self.commitment
    }

    /// Check if the share is still valid based on expiration time
    pub fn is_valid(&self, max_age_secs: u64) -> bool {
        let current_time = current_timestamp();
        current_time - self.timestamp <= max_age_secs
    }

    /// Encrypt the share with a given key
    pub fn encrypt(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut share_bytes = bincode::serialize(self).unwrap(); // Serialize the share
        let mut cipher = Aes256Ctr::new(key.into(), &[0u8; 16].into());
        cipher.apply_keystream(&mut share_bytes);
        share_bytes
    }

    /// Decrypt an encrypted share with a given key
    pub fn decrypt(encrypted_share: &[u8], key: &[u8; 32]) -> Share {
        let mut share_bytes = encrypted_share.to_vec();
        let mut cipher = Aes256Ctr::new(key.into(), &[0u8; 16].into());
        cipher.apply_keystream(&mut share_bytes);
        bincode::deserialize(&share_bytes).unwrap()
    }
}

fn main() {
    let secret = BigInt::from(1234567890); // Example secret
    let threshold = 3; // Minimum number of shares needed to reconstruct the secret
    let total_shares = 5; // Total number of shares generated

    // Initialize the Threshold Secret Sharing instance
    let tss = ThresholdSecretSharing::new(threshold, total_shares);

    // Split the secret into shares
    let shares = tss.split_secret(&secret);

    // Log each generated share to demonstrate it working
    println!("Generated Shares:");
    for (i, share) in shares.iter().enumerate() {
        println!(
            "Share {}: x = {}, y = {}, commitment = {:?}, timestamp = {}",
            i + 1,
            share.x,
            share.y,
            share.commitment,
            share.timestamp
        );
    }

    // Encrypt each share with a symmetric key (for example purposes, we use a static key)
    let key = [0u8; 32]; // Replace with a securely generated key in a real application
    let encrypted_shares: Vec<Vec<u8>> = shares.iter().map(|share| share.encrypt(&key)).collect();

    // Log encrypted shares
    println!("\nEncrypted Shares:");
    for (i, encrypted_share) in encrypted_shares.iter().enumerate() {
        println!("Encrypted Share {}: {:?}", i + 1, encrypted_share);
    }

    // Decrypt one share and verify its integrity
    let decrypted_share = Share::decrypt(&encrypted_shares[0], &key);
    println!("\nDecrypted and Verified Share:");
    println!(
        "x = {}, y = {}, commitment = {:?}, timestamp = {}, valid = {}",
        decrypted_share.x,
        decrypted_share.y,
        decrypted_share.commitment,
        decrypted_share.timestamp,
        decrypted_share.verify_commitment()
    );

    // Check if the decrypted share is still valid based on a set expiration time
    let max_age_secs = 60 * 60; // 1 hour
    println!("Is the decrypted share still valid? {}", decrypted_share.is_valid(max_age_secs));

    // Reconstruct the secret from a subset of valid, decrypted shares
    let reconstructed_secret = tss.reconstruct_secret(&[decrypted_share.clone(), shares[1].clone(), shares[2].clone()]);
    println!("\nOriginal Secret: {}", secret);
    println!("Reconstructed Secret: {}", reconstructed_secret);
}
