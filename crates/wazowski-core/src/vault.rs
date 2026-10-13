//! Encrypted secret storage.
//!
//! Wazowski keeps connection passwords and private keys in a single file,
//! encrypted at rest so it is safe to back up or sync. The file is decrypted
//! with a master key derived from the user's master password with Argon2id;
//! the contents are sealed with XChaCha20-Poly1305, which authenticates them so
//! tampering is detected on unlock.
//!
//! The master key can also be cached in the OS keyring (see [`keyring`]), so the
//! vault opens without a prompt while the desktop login session is unlocked.
//!
//! On-disk layout of the vault file:
//!
//! ```text
//! WZVAULT1            8-byte magic
//! salt                16 bytes (Argon2id salt)
//! m_cost t_cost p_cost 3 * u32 little-endian (Argon2id parameters)
//! nonce               24 bytes (XChaCha20-Poly1305 nonce)
//! ciphertext          the encrypted JSON document, with its 16-byte tag
//! ```
//!
//! The header fields before the ciphertext are authenticated as associated
//! data, so the parameters cannot be altered without unlock failing.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"WZVAULT1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + 12 + NONCE_LEN;

/// Service and account names under which the cached master key lives in the OS keyring.
const KEYRING_SERVICE: &str = "org.wazowski.vault";
const KEYRING_ACCOUNT: &str = "master-key";

/// A 32-byte key that wipes itself from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MasterKey([u8; KEY_LEN]);

/// A secret entry: a connection password, or a named private key with its optional passphrase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Secret {
    /// A login password.
    Password(String),
    /// A private key in PEM/OpenSSH form, with an optional passphrase to decrypt it.
    PrivateKey {
        pem: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
}

/// The decrypted contents of the vault: named secrets.
///
/// Not `Zeroize` itself (its `BTreeMap` isn't), but each [`Secret`] it holds
/// wipes itself on drop, so dropping the document clears the secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Document {
    secrets: BTreeMap<String, Secret>,
}

/// Argon2id cost parameters, stored in the file so an old vault still opens if defaults change.
#[derive(Clone, Copy)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // OWASP's recommended Argon2id baseline: 19 MiB, 2 iterations, 1 lane.
        Self {
            m_cost: Params::DEFAULT_M_COST,
            t_cost: Params::DEFAULT_T_COST,
            p_cost: Params::DEFAULT_P_COST,
        }
    }
}

/// An open vault, held decrypted in memory. Writes are flushed to disk on each change.
pub struct Vault {
    path: PathBuf,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    key: MasterKey,
    doc: Document,
}

impl Vault {
    /// Default vault location: the platform data directory, e.g.
    /// `~/.local/share/wazowski/vault.enc` on Linux.
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a data directory")?;
        Ok(dirs.data_dir().join("vault.enc"))
    }

    /// Whether a vault file already exists at `path`.
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Creates a brand-new empty vault encrypted with `master_password` and writes it to `path`.
    pub fn create(path: PathBuf, master_password: &str) -> Result<Self> {
        if Self::exists(&path) {
            bail!("a vault already exists at {}", path.display());
        }
        let mut salt = [0u8; SALT_LEN];
        rand::fill(&mut salt);
        let kdf = KdfParams::default();
        let key = derive_key(master_password, &salt, kdf)?;
        let vault = Self { path, salt, kdf, key, doc: Document::default() };
        vault.save()?;
        Ok(vault)
    }

    /// Opens an existing vault at `path` with `master_password`.
    ///
    /// Returns [`VaultError::BadPassword`] if the password is wrong or the file
    /// has been tampered with (the two are indistinguishable by design).
    pub fn open(path: PathBuf, master_password: &str) -> Result<Self, VaultError> {
        let bytes = fs::read(&path).map_err(VaultError::Io)?;
        let parsed = ParsedFile::parse(&bytes)?;
        let key = derive_key(master_password, &parsed.salt, parsed.kdf)
            .map_err(VaultError::Other)?;
        let doc = decrypt(&key, &parsed)?;
        Ok(Self { path, salt: parsed.salt, kdf: parsed.kdf, key, doc })
    }

    /// Changes the master password, re-deriving the key with a fresh salt and re-encrypting.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        rand::fill(&mut self.salt);
        self.key = derive_key(new_password, &self.salt, self.kdf)?;
        self.save()
    }

    /// Stores (or replaces) a secret under `name` and flushes to disk.
    pub fn put(&mut self, name: &str, secret: Secret) -> Result<()> {
        self.doc.secrets.insert(name.to_owned(), secret);
        self.save()
    }

    /// Fetches a secret by name.
    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.doc.secrets.get(name)
    }

    /// Removes a secret, flushing to disk. Returns whether it existed.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let existed = self.doc.secrets.remove(name).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    /// Names of all stored secrets, sorted.
    pub fn names(&self) -> Vec<String> {
        self.doc.secrets.keys().cloned().collect()
    }

    /// Caches the master key in the OS keyring so the vault can later be opened
    /// without the master password while the login session is unlocked.
    pub fn enable_keyring_unlock(&self) -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .context("the OS keyring is unavailable")?;
        // Store key material plus the salt so a later open can verify it still
        // matches this vault file (a restored backup would have a different salt).
        let mut blob = Vec::with_capacity(SALT_LEN + KEY_LEN);
        blob.extend_from_slice(&self.salt);
        blob.extend_from_slice(&self.key.0);
        entry.set_secret(&blob).context("could not write to the OS keyring")?;
        blob.zeroize();
        Ok(())
    }

    /// Removes any cached master key from the OS keyring.
    pub fn disable_keyring_unlock() -> Result<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
            .context("the OS keyring is unavailable")?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!(e).context("could not update the OS keyring")),
        }
    }

    /// Opens the vault using a master key cached in the OS keyring, if one is
    /// present and matches this vault file. Returns `Ok(None)` when no usable
    /// cached key exists, so the caller can fall back to asking for the password.
    pub fn open_with_keyring(path: PathBuf) -> Result<Option<Self>, VaultError> {
        let entry = match keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT) {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        let blob = match entry.get_secret() {
            Ok(blob) => Zeroizing::new(blob),
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(VaultError::Other(anyhow!(e))),
        };
        if blob.len() != SALT_LEN + KEY_LEN {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(VaultError::Io)?;
        let parsed = ParsedFile::parse(&bytes)?;
        // A cached key for a different vault file (e.g. a restored backup) is stale.
        if parsed.salt != blob[..SALT_LEN] {
            return Ok(None);
        }
        let mut key = MasterKey([0u8; KEY_LEN]);
        key.0.copy_from_slice(&blob[SALT_LEN..]);
        let doc = decrypt(&key, &parsed)?;
        Ok(Some(Self { path, salt: parsed.salt, kdf: parsed.kdf, key, doc }))
    }

    /// Encrypts the current document and writes it to the vault file atomically.
    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }

        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce);
        let header = file_header(&self.salt, self.kdf, &nonce);

        let plaintext = Zeroizing::new(
            serde_json::to_vec(&self.doc).context("could not serialize the vault")?,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key.0)
            .map_err(|e| anyhow!("invalid master key: {e}"))?;
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: &plaintext, aad: &header })
            .map_err(|_| anyhow!("encryption failed"))?;

        let mut out = header;
        out.extend_from_slice(&ciphertext);
        write_atomic(&self.path, &out)
            .with_context(|| format!("could not write {}", self.path.display()))
    }
}

/// Error cases a caller must distinguish when opening a vault.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Wrong master password, or the file was tampered with.
    #[error("the master password is incorrect, or the vault file is corrupt")]
    BadPassword,
    /// The file is not a vault (bad magic) or is truncated.
    #[error("not a valid vault file")]
    Malformed,
    #[error(transparent)]
    Io(io::Error),
    #[error(transparent)]
    Other(anyhow::Error),
}

/// The parsed, still-encrypted contents of a vault file.
struct ParsedFile<'a> {
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
    /// The header bytes, reused as associated data on decrypt.
    header: Vec<u8>,
}

impl<'a> ParsedFile<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
            return Err(VaultError::Malformed);
        }
        let mut pos = MAGIC.len();
        let mut take = |n: usize| {
            let slice = &bytes[pos..pos + n];
            pos += n;
            slice
        };
        let salt: [u8; SALT_LEN] = take(SALT_LEN).try_into().expect("checked length");
        let m_cost = u32::from_le_bytes(take(4).try_into().unwrap());
        let t_cost = u32::from_le_bytes(take(4).try_into().unwrap());
        let p_cost = u32::from_le_bytes(take(4).try_into().unwrap());
        let nonce: [u8; NONCE_LEN] = take(NONCE_LEN).try_into().expect("checked length");
        Ok(Self {
            salt,
            kdf: KdfParams { m_cost, t_cost, p_cost },
            nonce,
            ciphertext: &bytes[HEADER_LEN..],
            header: bytes[..HEADER_LEN].to_vec(),
        })
    }
}

/// Decrypts a parsed file into a [`Document`], mapping an auth failure to [`VaultError::BadPassword`].
fn decrypt(key: &MasterKey, parsed: &ParsedFile) -> Result<Document, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|e| VaultError::Other(anyhow!("invalid master key: {e}")))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(parsed.nonce),
                Payload { msg: parsed.ciphertext, aad: &parsed.header },
            )
            .map_err(|_| VaultError::BadPassword)?,
    );
    serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Other(anyhow!(e).context("vault contents are not valid")))
}

/// Builds the authenticated file header (everything before the ciphertext).
fn file_header(salt: &[u8; SALT_LEN], kdf: KdfParams, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(salt);
    header.extend_from_slice(&kdf.m_cost.to_le_bytes());
    header.extend_from_slice(&kdf.t_cost.to_le_bytes());
    header.extend_from_slice(&kdf.p_cost.to_le_bytes());
    header.extend_from_slice(nonce);
    header
}

/// Derives the 32-byte master key from the password and salt with Argon2id.
fn derive_key(password: &str, salt: &[u8], kdf: KdfParams) -> Result<MasterKey> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow!("invalid Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = MasterKey([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key.0)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Writes `data` to `path` via a temp file and rename, so a crash can't leave a half-written vault.
fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("enc.tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // A deliberately cheap KDF so tests stay fast; real vaults use the defaults.
    fn fast_vault(path: PathBuf, password: &str) -> Vault {
        let mut salt = [0u8; SALT_LEN];
        rand::fill(&mut salt);
        let kdf = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };
        let key = derive_key(password, &salt, kdf).unwrap();
        let vault = Vault { path, salt, kdf, key, doc: Document::default() };
        vault.save().unwrap();
        vault
    }

    #[test]
    fn roundtrip_create_and_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");

        let mut vault = Vault::create(path.clone(), "correct horse").unwrap();
        vault.put("prod-root", Secret::Password("hunter2".into())).unwrap();
        vault
            .put(
                "deploy-key",
                Secret::PrivateKey { pem: "-----BEGIN-----\nx\n".into(), passphrase: Some("pw".into()) },
            )
            .unwrap();
        drop(vault);

        let reopened = Vault::open(path, "correct horse").unwrap();
        assert_eq!(reopened.names(), vec!["deploy-key", "prod-root"]);
        assert_eq!(reopened.get("prod-root"), Some(&Secret::Password("hunter2".into())));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        Vault::create(path.clone(), "right").unwrap();
        match Vault::open(path, "wrong").map(|_| ()) {
            Err(VaultError::BadPassword) => {}
            other => panic!("expected BadPassword, got {other:?}"),
        }
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        fast_vault(path.clone(), "pw");

        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff; // flip a bit in the tag/ciphertext
        fs::write(&path, &bytes).unwrap();

        match Vault::open(path, "pw").map(|_| ()) {
            Err(VaultError::BadPassword) => {}
            other => panic!("expected BadPassword from tampered file, got {other:?}"),
        }
    }

    #[test]
    fn header_tampering_is_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        fast_vault(path.clone(), "pw");

        // Flip a bit in the KDF params, which are authenticated as associated data.
        let mut bytes = fs::read(&path).unwrap();
        bytes[MAGIC.len() + SALT_LEN] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(Vault::open(path, "pw"), Err(VaultError::BadPassword)));
    }

    #[test]
    fn not_a_vault_is_malformed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        fs::write(&path, b"nonsense").unwrap();
        assert!(matches!(Vault::open(path, "pw"), Err(VaultError::Malformed)));
    }

    #[test]
    fn change_password_reencrypts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = fast_vault(path.clone(), "old");
        vault.put("x", Secret::Password("secret".into())).unwrap();
        let old_salt = vault.salt;
        vault.change_password("new").unwrap();
        assert_ne!(vault.salt, old_salt, "salt should be rotated");

        assert!(matches!(Vault::open(path.clone(), "old"), Err(VaultError::BadPassword)));
        let reopened = Vault::open(path, "new").unwrap();
        assert_eq!(reopened.get("x"), Some(&Secret::Password("secret".into())));
    }

    // Touches the real OS keyring, so it is not run by default. Run with:
    //   cargo test -p wazowski-core -- --ignored keyring
    #[test]
    #[ignore = "uses the real OS keyring"]
    fn keyring_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = Vault::create(path.clone(), "master").unwrap();
        vault.put("x", Secret::Password("s3cret".into())).unwrap();
        vault.enable_keyring_unlock().unwrap();
        drop(vault);

        let opened = Vault::open_with_keyring(path).unwrap().expect("cached key should open it");
        assert_eq!(opened.get("x"), Some(&Secret::Password("s3cret".into())));

        Vault::disable_keyring_unlock().unwrap();
    }

    #[test]
    fn remove_secret() {
        let dir = tempdir().unwrap();
        let mut vault = fast_vault(dir.path().join("vault.enc"), "pw");
        vault.put("a", Secret::Password("1".into())).unwrap();
        assert!(vault.remove("a").unwrap());
        assert!(!vault.remove("a").unwrap());
        assert!(vault.get("a").is_none());
    }
}
