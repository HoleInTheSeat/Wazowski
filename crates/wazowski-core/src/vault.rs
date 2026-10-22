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

/// A stored credential: a password or a private key, each with an optional
/// username. When a session references the entry, a username here overrides the
/// one on the session (like MobaXterm's named credentials).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Secret {
    /// A login password, with an optional username.
    Password {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        password: String,
    },
    /// An SSH keypair: a private key in PEM/OpenSSH form, an optional public key
    /// (OpenSSH single-line form), an optional passphrase for the private key,
    /// and an optional username override.
    PrivateKey {
        pem: String,
        /// The matching public key, if saved alongside the private one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
    /// An access token: a GitHub HTTPS token, API key, or similar bearer secret,
    /// with an optional username (used as the HTTPS username for git; ignored by
    /// bearer-style APIs).
    Token {
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
    },
}

/// The broad kind of a [`Secret`], used to group entries in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretCategory {
    Password,
    Key,
    Token,
}

impl Secret {
    /// The username this credential overrides the session's with, if any.
    pub fn username(&self) -> Option<&str> {
        match self {
            Secret::Password { username, .. }
            | Secret::PrivateKey { username, .. }
            | Secret::Token { username, .. } => username.as_deref(),
        }
    }

    /// The saved public key, for a keypair that has one.
    pub fn public_key(&self) -> Option<&str> {
        match self {
            Secret::PrivateKey { public, .. } => public.as_deref(),
            Secret::Password { .. } | Secret::Token { .. } => None,
        }
    }

    /// The token string, for a token entry.
    pub fn token(&self) -> Option<&str> {
        match self {
            Secret::Token { token, .. } => Some(token),
            _ => None,
        }
    }

    /// This secret's broad category, for grouping.
    pub fn category(&self) -> SecretCategory {
        match self {
            Secret::Password { .. } => SecretCategory::Password,
            Secret::PrivateKey { .. } => SecretCategory::Key,
            Secret::Token { .. } => SecretCategory::Token,
        }
    }
}

/// One stored vault entry: an editable display `name` plus its secret. The map
/// key (outside) is the entry's stable id (a slug derived from the first name).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    name: String,
    secret: Secret,
}

/// An entry's id, display name, and category, for listing/choosing in the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub id: String,
    pub name: String,
    pub category: SecretCategory,
}

/// The decrypted contents of the vault.
///
/// Not `Zeroize` itself (its `BTreeMap` isn't), but each [`Secret`] it holds
/// wipes itself on drop, so dropping the document clears the secrets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Document {
    /// Current format: stable id (slug) -> entry (display name + secret).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    entries: BTreeMap<String, Entry>,
    /// Legacy format: name -> secret. Read on load and migrated into `entries`
    /// (assigning slug ids); never written back.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    secrets: BTreeMap<String, Secret>,
}

impl Document {
    /// Migrates any legacy `secrets` (keyed by name) into id-keyed `entries`,
    /// giving each a slug id. Returns whether anything was migrated (so the
    /// caller can persist the new format).
    fn migrate(&mut self) -> bool {
        if self.secrets.is_empty() {
            return false;
        }
        let legacy = std::mem::take(&mut self.secrets);
        for (name, secret) in legacy {
            let id = unique_id(&slugify(&name), &self.entries);
            self.entries.insert(id, Entry { name, secret });
        }
        true
    }
}

/// Turns a display name into an id slug: lowercase, non-alphanumeric runs become
/// a single `-`, trimmed. Empty results fall back to `entry`.
fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = true; // true suppresses a leading dash
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() { "entry".to_owned() } else { slug }
}

/// A slug not already used as a key in `existing`; appends `-2`, `-3`, … if taken.
fn unique_id(base: &str, existing: &BTreeMap<String, Entry>) -> String {
    if !existing.contains_key(base) {
        return base.to_owned();
    }
    (2..).map(|n| format!("{base}-{n}")).find(|c| !existing.contains_key(c)).unwrap()
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
        let mut vault = Self { path, salt: parsed.salt, kdf: parsed.kdf, key, doc };
        vault.migrate_format();
        Ok(vault)
    }

    /// If the decrypted document is in the legacy (name-keyed) format, assign
    /// stable ids and persist the new format. Best-effort: a failed save leaves
    /// the in-memory doc migrated (so this session works) and retries next save.
    fn migrate_format(&mut self) {
        if self.doc.migrate() {
            let _ = self.save();
        }
    }

    /// Changes the master password, re-deriving the key with a fresh salt and re-encrypting.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        rand::fill(&mut self.salt);
        self.key = derive_key(new_password, &self.salt, self.kdf)?;
        self.save()
    }

    /// Fetches a secret by its stable id.
    pub fn get(&self, id: &str) -> Option<&Secret> {
        self.doc.entries.get(id).map(|e| &e.secret)
    }

    /// Resolves a reference that may be an id (preferred) or, for legacy/shared
    /// references, a display name. Ids win over names on any overlap.
    pub fn resolve(&self, reference: &str) -> Option<&Secret> {
        if let Some(e) = self.doc.entries.get(reference) {
            return Some(&e.secret);
        }
        self.doc.entries.values().find(|e| e.name == reference).map(|e| &e.secret)
    }

    /// The id of the entry currently named `name` (first match), if any. Used to
    /// migrate legacy name-based references to ids.
    pub fn id_for_name(&self, name: &str) -> Option<&str> {
        self.doc.entries.iter().find(|(_, e)| e.name == name).map(|(id, _)| id.as_str())
    }

    /// The display name for an id.
    pub fn name_of(&self, id: &str) -> Option<&str> {
        self.doc.entries.get(id).map(|e| e.name.as_str())
    }

    /// Whether `name` (case-insensitive) is already used by another entry.
    pub fn name_taken(&self, name: &str, except_id: Option<&str>) -> bool {
        let lower = name.trim().to_lowercase();
        self.doc
            .entries
            .iter()
            .any(|(id, e)| e.name.to_lowercase() == lower && Some(id.as_str()) != except_id)
    }

    /// All entries (id + name), sorted by name (case-insensitive).
    pub fn entries(&self) -> Vec<EntryInfo> {
        let mut v: Vec<EntryInfo> = self
            .doc
            .entries
            .iter()
            .map(|(id, e)| EntryInfo {
                id: id.clone(),
                name: e.name.clone(),
                category: e.secret.category(),
            })
            .collect();
        v.sort_by_key(|e| e.name.to_lowercase());
        v
    }

    /// Adds a new entry, returning its generated stable id. Errors if the name
    /// is empty or already used.
    pub fn add(&mut self, name: &str, secret: Secret) -> Result<String> {
        let name = name.trim();
        if name.is_empty() {
            bail!("the entry needs a name");
        }
        if self.name_taken(name, None) {
            bail!("an entry named '{name}' already exists");
        }
        let id = unique_id(&slugify(name), &self.doc.entries);
        self.doc.entries.insert(id.clone(), Entry { name: name.to_owned(), secret });
        self.save()?;
        Ok(id)
    }

    /// Adds an entry under an *explicit* id — used when a session (often a shared
    /// one) references an entry id that doesn't exist here yet, so the created
    /// entry matches exactly regardless of the chosen display name. Errors if the
    /// id or the name is already taken.
    pub fn add_with_id(&mut self, id: &str, name: &str, secret: Secret) -> Result<()> {
        let name = name.trim();
        if id.is_empty() {
            bail!("the entry needs an id");
        }
        if name.is_empty() {
            bail!("the entry needs a name");
        }
        if self.doc.entries.contains_key(id) {
            bail!("an entry with id '{id}' already exists");
        }
        if self.name_taken(name, None) {
            bail!("an entry named '{name}' already exists");
        }
        self.doc.entries.insert(id.to_owned(), Entry { name: name.to_owned(), secret });
        self.save()
    }

    /// Replaces an existing entry's secret value (keeping its id and name).
    pub fn update_secret(&mut self, id: &str, secret: Secret) -> Result<()> {
        let entry = self.doc.entries.get_mut(id).context("that vault entry no longer exists")?;
        entry.secret = secret;
        self.save()
    }

    /// Renames an entry (its id stays the same). Errors if the new name is empty
    /// or already used by another entry.
    pub fn rename(&mut self, id: &str, new_name: &str) -> Result<()> {
        let new_name = new_name.trim();
        if new_name.is_empty() {
            bail!("the entry needs a name");
        }
        if self.name_taken(new_name, Some(id)) {
            bail!("an entry named '{new_name}' already exists");
        }
        let entry = self.doc.entries.get_mut(id).context("that vault entry no longer exists")?;
        entry.name = new_name.to_owned();
        self.save()
    }

    /// Removes an entry by id, flushing to disk. Returns whether it existed.
    pub fn remove(&mut self, id: &str) -> Result<bool> {
        let existed = self.doc.entries.remove(id).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
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
        let mut vault = Self { path, salt: parsed.salt, kdf: parsed.kdf, key, doc };
        vault.migrate_format();
        Ok(Some(vault))
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
        let root_id = vault
            .add("prod root", Secret::Password { username: None, password: "hunter2".into() })
            .unwrap();
        assert_eq!(root_id, "prod-root", "id is a slug of the name");
        vault
            .add(
                "deploy key",
                Secret::PrivateKey {
                    pem: "-----BEGIN-----\nx\n".into(),
                    public: Some("ssh-ed25519 AAAA deploy".into()),
                    passphrase: Some("pw".into()),
                    username: Some("deploy".into()),
                },
            )
            .unwrap();
        drop(vault);

        let reopened = Vault::open(path, "correct horse").unwrap();
        let names: Vec<String> = reopened.entries().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["deploy key", "prod root"]);
        assert_eq!(
            reopened.get("prod-root"),
            Some(&Secret::Password { username: None, password: "hunter2".into() })
        );
        // The keypair's public key survives the round-trip.
        assert_eq!(reopened.get("deploy-key").and_then(Secret::public_key), Some("ssh-ed25519 AAAA deploy"));
        // Resolution also works by name (for legacy/shared references).
        assert!(reopened.resolve("prod root").is_some());
    }

    #[test]
    fn token_roundtrip_and_category() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = Vault::create(path.clone(), "pw").unwrap();
        let id = vault
            .add(
                "GitHub token",
                Secret::Token { token: "ghp_abc123".into(), username: Some("octocat".into()) },
            )
            .unwrap();
        assert_eq!(id, "github-token");
        drop(vault);

        let reopened = Vault::open(path, "pw").unwrap();
        let secret = reopened.get("github-token").unwrap();
        assert_eq!(secret.token(), Some("ghp_abc123"));
        assert_eq!(secret.username(), Some("octocat"));
        assert_eq!(secret.public_key(), None);
        assert_eq!(secret.category(), SecretCategory::Token);
    }

    #[test]
    fn rename_keeps_id_and_secret() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = Vault::create(path, "pw").unwrap();
        let id = vault
            .add("VNC password", Secret::Password { username: None, password: "p".into() })
            .unwrap();
        assert_eq!(id, "vnc-password");
        vault.rename(&id, "VNC login").unwrap();
        // Same id still resolves to the same secret; the display name changed.
        assert_eq!(vault.name_of(&id), Some("VNC login"));
        assert!(vault.get(&id).is_some());
        // A duplicate name is refused.
        vault.add("Other", Secret::Password { username: None, password: "q".into() }).unwrap();
        assert!(vault.rename(&id, "Other").is_err());
    }

    #[test]
    fn add_with_id_forces_the_id_regardless_of_name() {
        let dir = tempdir().unwrap();
        let mut vault = Vault::create(dir.path().join("v.enc"), "pw").unwrap();
        vault
            .add_with_id(
                "vnc-password",
                "My VNC login",
                Secret::Password { username: None, password: "p".into() },
            )
            .unwrap();
        // The id is exactly what was requested, even though the name differs.
        assert_eq!(vault.name_of("vnc-password"), Some("My VNC login"));
        assert!(vault.get("vnc-password").is_some());
        // A session referencing "vnc-password" now resolves.
        assert!(vault.resolve("vnc-password").is_some());
        // Re-adding the same id fails.
        assert!(
            vault
                .add_with_id("vnc-password", "other", Secret::Password { username: None, password: "x".into() })
                .is_err()
        );
    }

    #[test]
    fn duplicate_slug_gets_suffix() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = Vault::create(path, "pw").unwrap();
        // Two distinct names that slugify the same get distinct ids.
        let a = vault.add("My Key", Secret::Password { username: None, password: "1".into() }).unwrap();
        let b = vault.add("my-key", Secret::Password { username: None, password: "2".into() }).unwrap();
        assert_eq!(a, "my-key");
        assert_eq!(b, "my-key-2");
    }

    #[test]
    fn slugify_cases() {
        assert_eq!(slugify("VNC password"), "vnc-password");
        assert_eq!(slugify("  Prod / DB  "), "prod-db");
        assert_eq!(slugify("a@@@b"), "a-b");
        assert_eq!(slugify("!!!"), "entry");
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
        vault.add("x", Secret::Password { username: None, password: "secret".into() }).unwrap();
        let old_salt = vault.salt;
        vault.change_password("new").unwrap();
        assert_ne!(vault.salt, old_salt, "salt should be rotated");

        assert!(matches!(Vault::open(path.clone(), "old"), Err(VaultError::BadPassword)));
        let reopened = Vault::open(path, "new").unwrap();
        assert_eq!(reopened.get("x"), Some(&Secret::Password { username: None, password: "secret".into() }));
    }

    // Touches the real OS keyring, so it is not run by default. Run with:
    //   cargo test -p wazowski-core -- --ignored keyring
    #[test]
    #[ignore = "uses the real OS keyring"]
    fn keyring_unlock_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = Vault::create(path.clone(), "master").unwrap();
        vault.add("x", Secret::Password { username: None, password: "s3cret".into() }).unwrap();
        vault.enable_keyring_unlock().unwrap();
        drop(vault);

        let opened = Vault::open_with_keyring(path).unwrap().expect("cached key should open it");
        assert_eq!(opened.get("x"), Some(&Secret::Password { username: None, password: "s3cret".into() }));

        Vault::disable_keyring_unlock().unwrap();
    }

    #[test]
    fn migrates_legacy_name_keyed_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let mut vault = fast_vault(path.clone(), "pw");
        // Simulate an old vault: secrets keyed by name in the legacy map.
        vault.doc.secrets.insert(
            "Prod DB".into(),
            Secret::Password { username: Some("admin".into()), password: "x".into() },
        );
        vault.save().unwrap();
        let salt = vault.salt;
        let kdf = vault.kdf;
        drop(vault);

        // Reopen with the same (fast) key material via open_with... emulate by
        // reading and decrypting through the normal open path.
        let key = derive_key("pw", &salt, kdf).unwrap();
        let bytes = fs::read(&path).unwrap();
        let parsed = ParsedFile::parse(&bytes).unwrap();
        let doc = decrypt(&key, &parsed).unwrap();
        let mut reopened = Vault { path, salt, kdf, key, doc };
        reopened.migrate_format();

        assert!(reopened.doc.secrets.is_empty(), "legacy map is migrated away");
        assert_eq!(reopened.get("prod-db").and_then(Secret::username), Some("admin"));
        assert_eq!(reopened.name_of("prod-db"), Some("Prod DB"));
    }

    #[test]
    fn remove_secret() {
        let dir = tempdir().unwrap();
        let mut vault = fast_vault(dir.path().join("vault.enc"), "pw");
        let id = vault.add("a", Secret::Password { username: None, password: "1".into() }).unwrap();
        assert!(vault.remove(&id).unwrap());
        assert!(!vault.remove(&id).unwrap());
        assert!(vault.get(&id).is_none());
    }
}
