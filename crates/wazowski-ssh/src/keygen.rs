//! SSH key pair generation, for creating keys to store in the vault.

use anyhow::{Context, Result};
use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};

/// A freshly generated key pair.
pub struct GeneratedKey {
    /// The private key in OpenSSH PEM form (store this in the vault).
    pub private_pem: String,
    /// The public key in single-line OpenSSH form (add this to the server).
    pub public_openssh: String,
}

/// Generates a new Ed25519 key pair with an optional comment.
pub fn generate_ed25519(comment: &str) -> Result<GeneratedKey> {
    let mut rng = rand::rng();
    let mut key =
        PrivateKey::random(&mut rng, Algorithm::Ed25519).context("key generation failed")?;
    if !comment.is_empty() {
        key.set_comment(comment);
    }
    let private_pem = key.to_openssh(LineEnding::LF).context("could not encode the key")?.to_string();
    let public_openssh = key.public_key().to_openssh().context("could not encode the public key")?;
    Ok(GeneratedKey { private_pem, public_openssh })
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{PrivateKey, PublicKey};

    #[test]
    fn generates_valid_ed25519() {
        let key = generate_ed25519("test@wazowski").unwrap();
        // The private key round-trips through the OpenSSH parser.
        let parsed = PrivateKey::from_openssh(&key.private_pem).unwrap();
        assert_eq!(parsed.algorithm().to_string(), "ssh-ed25519");
        // The public key parses and matches.
        let public = PublicKey::from_openssh(&key.public_openssh).unwrap();
        assert_eq!(public.key_data(), parsed.public_key().key_data());
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn two_keys_differ() {
        let a = generate_ed25519("").unwrap();
        let b = generate_ed25519("").unwrap();
        assert_ne!(a.private_pem, b.private_pem);
    }
}
