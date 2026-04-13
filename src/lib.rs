//! SHA256-based commit-reveal scheme for fair P2P verification.
//!
//! A [commit-reveal scheme](https://en.wikipedia.org/wiki/Commitment_scheme) lets
//! one party commit to a value without revealing it, then prove what was committed
//! later. This prevents cheating in peer-to-peer protocols where no trusted server
//! exists.
//!
//! # Protocol
//!
//! 1. Generator picks a payload and random nonce (32 bytes)
//! 2. Computes commitment = SHA256(payload || nonce)
//! 3. Sends commitment hash to peer
//! 4. Peer acknowledges receipt
//! 5. Generator reveals payload and nonce
//! 6. Peer verifies SHA256(payload || nonce) == commitment
//! 7. Both accept the payload
//!
//! If the generator doesn't reveal within a timeout, they forfeit.
//!
//! # Example
//!
//! ```
//! use commit_reveal::Commitment;
//!
//! // Generator: create a commitment
//! let commitment = Commitment::new(b"secret value");
//! let hash_to_send = commitment.hash;
//!
//! // ... send hash to peer, receive ack ...
//!
//! // Generator: reveal payload and nonce
//! let payload = &commitment.payload;
//! let nonce = &commitment.nonce;
//!
//! // Verifier: check the reveal matches the commitment
//! assert!(Commitment::verify(&hash_to_send, payload, nonce));
//! ```

use std::fmt;

use rand::RngExt;
use sha2::{Digest, Sha256};

/// A commitment binding an arbitrary byte payload to a SHA256 hash via a random nonce.
///
/// # Example
///
/// ```
/// use commit_reveal::Commitment;
///
/// let commitment = Commitment::new(&[1, 2, 3]);
///
/// // Verification succeeds with correct payload and nonce
/// assert!(Commitment::verify(&commitment.hash, &commitment.payload, &commitment.nonce));
///
/// // Verification fails with tampered payload
/// assert!(!Commitment::verify(&commitment.hash, &[1, 2, 4], &commitment.nonce));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commitment {
    /// The committed payload.
    pub payload: Vec<u8>,
    /// Random nonce used for this commitment.
    pub nonce: [u8; 32],
    /// SHA256(payload || nonce).
    pub hash: [u8; 32],
}

/// Displays the commitment hash as a hex string, e.g. `Commitment(a1b2c3d4...)`.
impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment(")?;
        for byte in &self.hash {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl Commitment {
    /// Create a commitment for an arbitrary byte payload.
    ///
    /// Generates a random 32-byte nonce and computes `SHA256(payload || nonce)`.
    pub fn new(payload: &[u8]) -> Self {
        let nonce: [u8; 32] = rand::rng().random();
        let hash = compute_hash(payload, &nonce);
        Self {
            payload: payload.to_vec(),
            nonce,
            hash,
        }
    }

    /// Verify that a revealed payload and nonce match a commitment hash.
    ///
    /// Returns `true` if `SHA256(payload || nonce) == commitment_hash`.
    pub fn verify(commitment_hash: &[u8; 32], payload: &[u8], nonce: &[u8; 32]) -> bool {
        let computed = compute_hash(payload, nonce);
        &computed == commitment_hash
    }

    /// Returns the commitment hash as a lowercase hex string (64 characters).
    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Compute `SHA256(payload || nonce)`.
pub fn compute_hash(payload: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.update(nonce);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_payload() {
        let commitment = Commitment::new(&[42]);
        assert_eq!(commitment.payload, vec![42]);
        assert_ne!(commitment.nonce, [0u8; 32]);
        assert!(Commitment::verify(
            &commitment.hash,
            &commitment.payload,
            &commitment.nonce
        ));
    }

    #[test]
    fn test_multi_byte_payload() {
        let payload = b"hello world";
        let commitment = Commitment::new(payload);
        assert_eq!(commitment.payload, payload.to_vec());
        assert!(Commitment::verify(
            &commitment.hash,
            &commitment.payload,
            &commitment.nonce
        ));
    }

    #[test]
    fn test_empty_payload() {
        let commitment = Commitment::new(&[]);
        assert!(commitment.payload.is_empty());
        assert!(Commitment::verify(
            &commitment.hash,
            &commitment.payload,
            &commitment.nonce
        ));
    }

    #[test]
    fn test_verification_fails_wrong_payload() {
        let commitment = Commitment::new(&[1, 2, 3]);

        assert!(!Commitment::verify(
            &commitment.hash,
            &[1, 2, 4],
            &commitment.nonce
        ));
    }

    #[test]
    fn test_verification_fails_wrong_nonce() {
        let commitment = Commitment::new(&[1, 2, 3]);

        let mut wrong_nonce = commitment.nonce;
        wrong_nonce[0] ^= 0xFF;
        assert!(!Commitment::verify(
            &commitment.hash,
            &commitment.payload,
            &wrong_nonce
        ));
    }

    #[test]
    fn test_display() {
        let commitment = Commitment::new(&[1]);
        let s = commitment.to_string();
        assert!(s.starts_with("Commitment("));
        assert!(s.ends_with(')'));
        // 64 hex chars for SHA256 + "Commitment(" + ")"
        assert_eq!(s.len(), 11 + 64 + 1);
    }

    #[test]
    fn test_hash_hex() {
        let commitment = Commitment::new(&[1]);
        let hex = commitment.hash_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_eq_and_hash() {
        use std::collections::HashSet;
        let commitment = Commitment::new(&[1, 2, 3]);
        let clone = commitment.clone();
        assert_eq!(commitment, clone);

        let mut set = HashSet::new();
        set.insert(commitment.clone());
        assert!(set.contains(&clone));
    }
}
