//! Ed25519 signing for the **signed ledger head**.
//!
//! The hash chain ([`crate::ledger`]) makes a ledger tamper-*evident* locally. Signing
//! its head makes the audit trail **non-repudiable**: an instance signs
//! `foreguard-head-v1\n{instance}\n{seq}\n{hash}` with a private key only it holds, and
//! the control plane verifies that signature against the instance's pinned public key.
//! A control-plane operator (or anyone who edits the database) then *cannot forge* a
//! valid head — they don't have the key — so undetectable rewriting is off the table.
//! The private key never leaves the instance; only the public key and signatures do.

use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};

/// The canonical head message. **Must** match the control plane's `headMessage`
/// byte-for-byte, so signatures verify across the Rust ↔ TypeScript boundary.
pub fn head_message(instance: &str, seq: i64, hash: &str) -> String {
    format!("foreguard-head-v1\n{instance}\n{seq}\n{hash}")
}

/// Generate a fresh 32-byte signing seed from the OS RNG.
pub fn generate_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("OS RNG failed: {e}"))?;
    Ok(seed)
}

/// Write a seed to `path` as base64, owner-only (0600) where the OS supports it.
pub fn write_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    use std::io::Write as _;
    let encoded = STANDARD.encode(seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing key file {}", path.display()))?;
        f.write_all(encoded.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, encoded)
            .with_context(|| format!("writing key file {}", path.display()))?;
    }
    Ok(())
}

/// A loaded Ed25519 signing key.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Load a key from a file holding a base64-encoded 32-byte seed.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading signing key {}", path.display()))?;
        let bytes = STANDARD
            .decode(raw.trim())
            .context("signing key is not valid base64")?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key seed must be exactly 32 bytes"))?;
        Ok(Self::from_seed(&seed))
    }

    /// The base64 public key (what the control plane pins on first signed report).
    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().to_bytes())
    }

    /// Sign a message, returning the base64 signature.
    pub fn sign_base64(&self, message: &str) -> String {
        STANDARD.encode(self.signing.sign(message.as_bytes()).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn sign_then_verify_roundtrips() {
        let seed = generate_seed().unwrap();
        let kp = KeyPair::from_seed(&seed);
        let msg = head_message("agent-1", 7, "deadbeef");
        let sig_b64 = kp.sign_base64(&msg);

        // Verify independently, the way the control plane does.
        let pk_bytes: [u8; 32] = STANDARD
            .decode(kp.public_base64())
            .unwrap()
            .try_into()
            .unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = STANDARD.decode(&sig_b64).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(msg.as_bytes(), &sig).is_ok());

        // A different message must not verify with the same signature.
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn load_roundtrips_through_a_file() {
        let seed = generate_seed().unwrap();
        let path = std::env::temp_dir().join(format!("fg_key_{}.key", std::process::id()));
        write_seed(&path, &seed).unwrap();
        let a = KeyPair::from_seed(&seed).public_base64();
        let b = KeyPair::load(&path).unwrap().public_base64();
        assert_eq!(a, b, "a loaded key yields the same public key");
        let _ = std::fs::remove_file(&path);
    }
}
