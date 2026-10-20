//! SSH key pair generation, for creating keys to store in the vault.

use anyhow::{Context, Result};
use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};

/// The key algorithm to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KeyAlgo {
    /// Ed25519 — modern, short, fast (the recommended default).
    #[default]
    Ed25519,
    /// RSA 4096 — maximum compatibility with older servers/appliances.
    Rsa,
    /// ECDSA on NIST P-256.
    Ecdsa,
}

impl KeyAlgo {
    /// A human-readable name for the UI.
    pub fn label(self) -> &'static str {
        match self {
            KeyAlgo::Ed25519 => "Ed25519",
            KeyAlgo::Rsa => "RSA 4096",
            KeyAlgo::Ecdsa => "ECDSA P-256",
        }
    }

    /// All algorithms, in presentation order.
    pub const ALL: [KeyAlgo; 3] = [KeyAlgo::Ed25519, KeyAlgo::Rsa, KeyAlgo::Ecdsa];

    fn algorithm(self) -> Algorithm {
        match self {
            KeyAlgo::Ed25519 => Algorithm::Ed25519,
            // `hash: None` names the key `ssh-rsa`; the signing hash is
            // negotiated per-connection (rsa-sha2-256/512) at auth time.
            KeyAlgo::Rsa => Algorithm::Rsa { hash: None },
            KeyAlgo::Ecdsa => Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
        }
    }
}

/// A freshly generated key pair.
pub struct GeneratedKey {
    /// The private key in OpenSSH PEM form (store this in the vault). Encrypted
    /// with the passphrase when one was given.
    pub private_pem: String,
    /// The public key in single-line OpenSSH form (add this to the server).
    pub public_openssh: String,
}

/// Generates a new key pair of the given algorithm, with an optional comment and
/// an optional passphrase that encrypts the stored private key.
pub fn generate(algo: KeyAlgo, comment: &str, passphrase: Option<&str>) -> Result<GeneratedKey> {
    let mut rng = rand::rng();
    let mut key =
        PrivateKey::random(&mut rng, algo.algorithm()).context("key generation failed")?;
    if !comment.is_empty() {
        key.set_comment(comment);
    }
    // The public key is the same whether or not the private half is encrypted,
    // so encode it before encrypting.
    let public_openssh =
        key.public_key().to_openssh().context("could not encode the public key")?;
    let key = match passphrase {
        Some(p) if !p.is_empty() => {
            key.encrypt(&mut rng, p).context("could not encrypt the private key")?
        }
        _ => key,
    };
    let private_pem =
        key.to_openssh(LineEnding::LF).context("could not encode the key")?.to_string();
    Ok(GeneratedKey { private_pem, public_openssh })
}

/// Generates a new Ed25519 key pair with an optional comment (no passphrase).
pub fn generate_ed25519(comment: &str) -> Result<GeneratedKey> {
    generate(KeyAlgo::Ed25519, comment, None)
}

/// Returns an OpenSSH private key that `ssh -i` can use without prompting: if the
/// input is an encrypted OpenSSH key it is decrypted with `passphrase`; an
/// already-unencrypted key is re-encoded as-is. Keys that aren't OpenSSH-format
/// (e.g. a classic `-----BEGIN RSA PRIVATE KEY-----` PEM) are returned unchanged
/// for `ssh` to handle directly.
pub fn to_unencrypted_openssh(pem: &str, passphrase: Option<&str>) -> Result<String> {
    let Ok(key) = PrivateKey::from_openssh(pem) else {
        // Not an OpenSSH key; hand it to ssh untouched.
        return Ok(pem.to_owned());
    };
    let key = if key.is_encrypted() {
        key.decrypt(passphrase.unwrap_or("")).context("could not decrypt the SSH key")?
    } else {
        key
    };
    Ok(key.to_openssh(LineEnding::LF).context("could not encode the SSH key")?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{PrivateKey, PublicKey};

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
    fn generates_rsa_and_ecdsa() {
        let rsa = generate(KeyAlgo::Rsa, "", None).unwrap();
        let parsed = PrivateKey::from_openssh(&rsa.private_pem).unwrap();
        assert_eq!(parsed.algorithm().to_string(), "ssh-rsa");
        assert!(rsa.public_openssh.starts_with("ssh-rsa "));

        let ecdsa = generate(KeyAlgo::Ecdsa, "", None).unwrap();
        let parsed = PrivateKey::from_openssh(&ecdsa.private_pem).unwrap();
        assert_eq!(parsed.algorithm().to_string(), "ecdsa-sha2-nistp256");
        assert!(ecdsa.public_openssh.starts_with("ecdsa-sha2-nistp256 "));
    }

    #[test]
    fn passphrase_encrypts_the_private_key() {
        let key = generate(KeyAlgo::Ed25519, "", Some("hunter2")).unwrap();
        let parsed = PrivateKey::from_openssh(&key.private_pem).unwrap();
        assert!(parsed.is_encrypted(), "a passphrase should encrypt the key");
        // The right passphrase decrypts it.
        assert!(parsed.decrypt("hunter2").is_ok());
        // The public key is still readable without the passphrase.
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn to_unencrypted_decrypts_and_passes_through() {
        // An encrypted key is decrypted to an unencrypted OpenSSH key.
        let enc = generate(KeyAlgo::Ed25519, "", Some("pw")).unwrap();
        let out = to_unencrypted_openssh(&enc.private_pem, Some("pw")).unwrap();
        let parsed = PrivateKey::from_openssh(&out).unwrap();
        assert!(!parsed.is_encrypted(), "output must be usable by ssh -i without a prompt");

        // An already-unencrypted key round-trips unchanged in meaning.
        let plain = generate(KeyAlgo::Ed25519, "", None).unwrap();
        let out = to_unencrypted_openssh(&plain.private_pem, None).unwrap();
        assert!(PrivateKey::from_openssh(&out).is_ok());

        // Non-OpenSSH text is passed through untouched for ssh to handle.
        assert_eq!(to_unencrypted_openssh("not a key", None).unwrap(), "not a key");
    }

    #[test]
    fn two_keys_differ() {
        let a = generate_ed25519("").unwrap();
        let b = generate_ed25519("").unwrap();
        assert_ne!(a.private_pem, b.private_pem);
    }
}
