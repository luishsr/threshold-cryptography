## Threshold Cryptography Library in Rust
A Rust-based library implementing threshold cryptography with Shamir's Secret Sharing, modular arithmetic, and additional security features. This library allows secure distribution of secrets by splitting them into multiple shares, requiring a subset of shares to reconstruct the original secret.

## Features

Shamir's Secret Sharing: Split a secret into n shares, requiring a threshold t to reconstruct the secret.

Modular Arithmetic: Uses a large prime modulus to ensure secure, finite-field calculations.

Hash-Based Commitments: Each share includes a hash commitment to verify its integrity.

Share Expiration: Optional expiration feature to make shares invalid after a specified time.

Encrypted Shares: Encrypt each share for secure transmission across untrusted channels.


##Dependencies
num-bigint: For large integer arithmetic.
rand: For secure random number generation.
sha2: For generating SHA-256 hash commitments.
aes and ctr: For AES-256 CTR encryption of shares.
serde and bincode: For serializing and deserializing shares.
