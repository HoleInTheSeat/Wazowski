//! Saved SSH session definitions and their on-disk store.
//!
//! Sessions live in `sessions.toml` in the config directory (e.g.
//! `~/.config/wazowski/sessions.toml` on Linux). The file is plain text and
//! holds no secrets: passwords and private keys are kept in the [`crate::Vault`]
//! and referenced here only by name, so several sessions can share one key.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod tree;

/// How a session authenticates to the remote host.
///
/// Current variants are `Prompt` and `Vault`. The `Agent`/`Password`/`Key`
/// variants are legacy: they still deserialize from older session files and are
/// normalized to the current model on load (see [`Auth::normalize`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Auth {
    /// Prompt for the password at connect time; nothing is stored. The session's
    /// `username` is offered as an editable default in the prompt.
    #[default]
    Prompt,
    /// Authenticate from a vault entry, referenced by its stable id. The entry's
    /// kind (password, SSH key, or token) determines how the connection is made.
    Vault {
        #[serde(default)]
        entry: String,
    },

    // ---- legacy variants: read on load, normalized away, never written ----
    /// Old: keys from the running SSH agent. Migrated to `Prompt`.
    Agent,
    /// Old: a password vault entry (an empty id meant "prompt at connect").
    Password {
        #[serde(default)]
        secret: String,
    },
    /// Old: an SSH key vault entry.
    Key {
        #[serde(default)]
        secret: String,
    },
}

impl Auth {
    /// Rewrites a legacy variant to the current model, returning whether it
    /// changed. `Agent` and empty-id `Password` become [`Auth::Prompt`]; a
    /// `Password`/`Key` with an id becomes [`Auth::Vault`].
    fn normalize(&mut self) -> bool {
        let replacement = match self {
            Auth::Agent => Some(Auth::Prompt),
            Auth::Password { secret } | Auth::Key { secret } => {
                if secret.trim().is_empty() {
                    Some(Auth::Prompt)
                } else {
                    Some(Auth::Vault { entry: std::mem::take(secret) })
                }
            }
            Auth::Prompt | Auth::Vault { .. } => None,
        };
        match replacement {
            Some(r) => {
                *self = r;
                true
            }
            None => false,
        }
    }

    /// The vault entry id this auth references, if it is a vault auth.
    pub fn vault_entry(&self) -> Option<&str> {
        match self {
            Auth::Vault { entry } => Some(entry.as_str()),
            _ => None,
        }
    }
}

/// The protocol a saved session connects with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// An SSH terminal session (the historical default).
    #[default]
    Ssh,
    /// Remote Desktop, opened in an external client.
    Rdp,
    /// VNC, opened in an external viewer.
    Vnc,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Rdp => "RDP",
            Protocol::Vnc => "VNC",
        }
    }

    /// The conventional default port for this protocol.
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
        }
    }
}

/// A saved connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Stable identifier, used as the vault-secret owner and for referencing. Hex, 16 chars.
    pub id: String,
    /// Display name shown in the sidebar.
    pub name: String,
    /// Folder path for grouping in the tree, e.g. `work/prod`. Empty means the root.
    #[serde(default)]
    pub folder: String,
    /// The connection protocol. Older session files without this field load as SSH.
    #[serde(default)]
    pub protocol: Protocol,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    /// Optional Windows domain for RDP (ignored by other protocols).
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub auth: Auth,
    /// Offer legacy SSH algorithms (SHA-1 KEX, CBC ciphers) for old equipment.
    #[serde(default)]
    pub legacy: bool,
    /// Optional custom icon (an emoji); empty uses the default.
    #[serde(default)]
    pub icon: String,
    /// Optional custom label color, as sRGB `[r, g, b]`.
    #[serde(default)]
    pub color: Option<[u8; 3]>,
    /// Remembered SFTP auto-refresh state for this session.
    #[serde(default)]
    pub sftp_auto_refresh: bool,
    /// VNC: observe only (don't send input).
    #[serde(default)]
    pub vnc_view_only: bool,
    /// VNC: encoding/quality preference.
    #[serde(default)]
    pub vnc_quality: VncQuality,
    /// RDP: desired width in pixels; `0` means fit the window.
    #[serde(default)]
    pub rdp_width: u16,
    /// RDP: desired height in pixels; `0` means fit the window.
    #[serde(default)]
    pub rdp_height: u16,
    /// RDP: visual-quality / bandwidth trade-off.
    #[serde(default)]
    pub rdp_quality: RdpQuality,
}

/// RDP visual-quality / bandwidth trade-off.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpQuality {
    /// Fastest: low color depth, all eye-candy disabled.
    Performance,
    /// Balanced (default): full color, heaviest effects disabled.
    #[default]
    Balanced,
    /// Best looking: full color, themes and font smoothing on.
    Quality,
}

/// VNC encoding/quality preference (maps to the backend's encoding set).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VncQuality {
    /// Balanced ZRLE-based encodings.
    #[default]
    Auto,
    /// Favor image fidelity (more bandwidth).
    High,
    /// Favor bandwidth over fidelity.
    Low,
}

fn default_port() -> u16 {
    22
}

impl Session {
    /// Creates a session with a fresh random id and default port/auth.
    pub fn new(name: impl Into<String>, host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id: new_id(),
            name: name.into(),
            folder: String::new(),
            protocol: Protocol::default(),
            host: host.into(),
            port: default_port(),
            username: username.into(),
            domain: String::new(),
            auth: Auth::default(),
            legacy: false,
            icon: String::new(),
            color: None,
            sftp_auto_refresh: false,
            vnc_view_only: false,
            vnc_quality: VncQuality::default(),
            rdp_width: 0,
            rdp_height: 0,
            rdp_quality: RdpQuality::default(),
        }
    }

    /// The `user@host:port` form, omitting the port when it is the default.
    pub fn address(&self) -> String {
        if self.port == default_port() {
            format!("{}@{}", self.username, self.host)
        } else {
            format!("{}@{}:{}", self.username, self.host, self.port)
        }
    }
}

/// A folder's custom appearance (icon emoji and/or label color).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderStyle {
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub color: Option<[u8; 3]>,
}

impl FolderStyle {
    pub fn is_empty(&self) -> bool {
        self.icon.is_empty() && self.color.is_none()
    }
}

/// A folder's stable identity and description, carried in its `.folder` file so
/// they travel with a shared source. Icon/color stay in [`FolderStyle`]; this
/// adds the UUID (so a folder keeps its identity across rename/move) and an
/// optional description.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderMeta {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl FolderMeta {
    pub fn is_empty(&self) -> bool {
        self.id.is_empty() && self.description.is_empty()
    }
}

/// An in-memory collection of sessions backed by a TOML file.
#[derive(Debug, Default)]
pub struct SessionStore {
    path: PathBuf,
    sessions: Vec<Session>,
    /// Explicit folders, so empty ones persist (sessions also imply folders).
    folders: Vec<String>,
    /// Per-folder custom icon/color, keyed by folder path.
    folder_styles: BTreeMap<String, FolderStyle>,
    /// Optional free-text description of this collection (used by shared sources,
    /// so it travels with the file and every user sees it).
    description: String,
    /// Optional custom header icon (an emoji) for this collection; empty uses the
    /// default. Like the description, it's stored in the file so a shared source's
    /// appearance travels and every user sees it.
    icon: String,
    /// Optional custom header color, as sRGB `[r, g, b]` (shared, like `icon`).
    color: Option<[u8; 3]>,
    /// Collection display name. For a shared source this is the source's name,
    /// stored in the tree's root `.folder` so it travels to every user. Empty for
    /// the local store (which takes its label from the UI). Only used by the tree
    /// format; the single-file format omits it when empty.
    name: String,
    /// Stable id of this collection (the tree's root `.folder` UUID). Empty until
    /// [`ensure_ids`](Self::ensure_ids) assigns one.
    id: String,
    /// Per-folder identity + description, keyed by folder path. Kept separate from
    /// `folder_styles` so the existing single-file format is unchanged.
    folder_meta: BTreeMap<String, FolderMeta>,
}

/// The serialized file shape: `[[session]]` tables plus a `folders` list.
#[derive(Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    icon: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    color: Option<[u8; 3]>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, rename = "session")]
    sessions: Vec<Session>,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    folder_styles: BTreeMap<String, FolderStyle>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    folder_meta: BTreeMap<String, FolderMeta>,
}

impl SessionStore {
    /// Default store location in the platform config directory.
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("sessions.toml"))
    }

    /// Loads the store from `path`, returning an empty store if the file does not exist.
    pub fn load(path: PathBuf) -> Result<Self> {
        let file = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<StoreFile>(&text)
                .with_context(|| format!("could not parse {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile::default(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        let mut store = Self {
            path,
            sessions: file.sessions,
            folders: file.folders,
            folder_styles: file.folder_styles,
            description: file.description,
            icon: file.icon,
            color: file.color,
            name: file.name,
            id: file.id,
            folder_meta: file.folder_meta,
        };
        // Migrate any legacy auth (agent / password / key) to the current model,
        // persisting best-effort so the file is upgraded for next time.
        let mut migrated = false;
        for s in &mut store.sessions {
            migrated |= s.auth.normalize();
        }
        if migrated {
            let _ = store.save();
        }
        Ok(store)
    }

    /// This collection's free-text description (empty if none).
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Sets the collection's description and saves.
    pub fn set_description(&mut self, description: impl Into<String>) -> Result<()> {
        self.description = description.into();
        self.save()
    }

    /// This collection's custom header icon (an emoji), empty if none. Stored in
    /// the file so a shared source's appearance travels to every user.
    pub fn icon(&self) -> &str {
        &self.icon
    }

    /// This collection's custom header color, if any (shared, like [`icon`]).
    pub fn color(&self) -> Option<[u8; 3]> {
        self.color
    }

    /// Sets the collection's icon and color (shared appearance) and saves.
    pub fn set_appearance(&mut self, icon: impl Into<String>, color: Option<[u8; 3]>) -> Result<()> {
        self.icon = icon.into();
        self.color = color;
        self.save()
    }

    /// The collection's display name (empty if none). For a shared source this is
    /// the source's name, carried in the tree's root `.folder`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The collection's stable id (the tree's root `.folder` UUID), empty until
    /// [`ensure_ids`](Self::ensure_ids) assigns one.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// A folder's stable identity + description, if recorded.
    pub fn folder_meta(&self, path: &str) -> Option<&FolderMeta> {
        self.folder_meta.get(path).filter(|m| !m.is_empty())
    }

    /// All folder paths including implied ancestors, so e.g. a session in
    /// `a/b/c` yields `a`, `a/b`, and `a/b/c`. Sorted, so parents precede children.
    pub fn all_folder_paths(&self) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for f in self.folders() {
            let mut acc = String::new();
            for seg in f.split('/') {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(seg);
                set.insert(acc.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Assigns a stable UUID to the collection root and to every folder (including
    /// implied ancestors) that lacks one. Returns whether anything was assigned.
    /// The tree format needs these ids so identity survives rename/move.
    pub fn ensure_ids(&mut self) -> bool {
        let mut changed = false;
        if self.id.is_empty() {
            self.id = new_id();
            changed = true;
        }
        for path in self.all_folder_paths() {
            let meta = self.folder_meta.entry(path).or_default();
            if meta.id.is_empty() {
                meta.id = new_id();
                changed = true;
            }
        }
        changed
    }

    /// The custom appearance for a folder, if any.
    pub fn folder_style(&self, path: &str) -> Option<&FolderStyle> {
        self.folder_styles.get(path).filter(|s| !s.is_empty())
    }

    /// Sets (or clears, when empty) a folder's custom appearance, and saves.
    pub fn set_folder_style(&mut self, path: &str, style: FolderStyle) -> Result<()> {
        if style.is_empty() {
            self.folder_styles.remove(path);
        } else {
            self.folder_styles.insert(path.to_owned(), style);
        }
        self.save()
    }

    /// All sessions, in stored order.
    pub fn all(&self) -> &[Session] {
        &self.sessions
    }

    /// Finds a session by id.
    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Adds or replaces a session (matched by id) and saves.
    pub fn upsert(&mut self, session: Session) -> Result<()> {
        match self.sessions.iter_mut().find(|s| s.id == session.id) {
            Some(existing) => *existing = session,
            None => self.sessions.push(session),
        }
        self.save()
    }

    /// Removes a session by id and saves. Returns whether it existed.
    pub fn remove(&mut self, id: &str) -> Result<bool> {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.id != id);
        let removed = self.sessions.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Groups sessions by their folder path, for building the sidebar tree.
    pub fn by_folder(&self) -> BTreeMap<&str, Vec<&Session>> {
        let mut map: BTreeMap<&str, Vec<&Session>> = BTreeMap::new();
        for session in &self.sessions {
            map.entry(session.folder.as_str()).or_default().push(session);
        }
        map
    }

    /// All non-root folder names, sorted and de-duplicated: explicit folders plus
    /// any implied by a session's folder.
    pub fn folders(&self) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = self.folders.iter().cloned().collect();
        for session in &self.sessions {
            if !session.folder.is_empty() {
                set.insert(session.folder.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Creates an empty folder (no-op if it already exists). Returns whether it was new.
    pub fn add_folder(&mut self, name: &str) -> Result<bool> {
        let name = name.trim();
        if name.is_empty() || self.folders.iter().any(|f| f == name) {
            return Ok(false);
        }
        self.folders.push(name.to_owned());
        self.save()?;
        Ok(true)
    }

    /// Removes a folder and all its subfolders, moving affected sessions to root.
    pub fn remove_folder(&mut self, name: &str) -> Result<()> {
        let prefix = format!("{name}/");
        self.folders.retain(|f| f != name && !f.starts_with(&prefix));
        self.folder_styles.retain(|f, _| f != name && !f.starts_with(&prefix));
        for session in &mut self.sessions {
            if session.folder == name || session.folder.starts_with(&prefix) {
                session.folder.clear();
            }
        }
        self.save()
    }

    /// Renames a folder (and re-paths its subfolders and the sessions within).
    pub fn rename_folder(&mut self, old: &str, new: &str) -> Result<()> {
        let new = new.trim();
        if new.is_empty() || new == old {
            return Ok(());
        }
        let prefix = format!("{old}/");
        let repath = |f: &str| -> Option<String> {
            if f == old {
                Some(new.to_owned())
            } else {
                f.strip_prefix(&prefix).map(|rest| format!("{new}/{rest}"))
            }
        };
        for folder in &mut self.folders {
            if let Some(updated) = repath(folder) {
                *folder = updated;
            }
        }
        if !self.folders.iter().any(|f| f == new) {
            self.folders.push(new.to_owned());
        }
        for session in &mut self.sessions {
            if let Some(updated) = repath(&session.folder) {
                session.folder = updated;
            }
        }
        let styles = std::mem::take(&mut self.folder_styles);
        self.folder_styles = styles
            .into_iter()
            .map(|(path, style)| (repath(&path).unwrap_or(path), style))
            .collect();
        self.save()
    }

    /// Moves a session to a folder (empty string for the root) and saves.
    pub fn move_to_folder(&mut self, id: &str, folder: &str) -> Result<()> {
        if let Some(session) = self.sessions.iter_mut().find(|s| s.id == id) {
            session.folder = folder.to_owned();
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        // A tree-backed (assembled) store has no single-file path; its persistence
        // is driven externally via `tree::sync_tree`, so in-memory mutations here
        // must not try to write a lone TOML file.
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        self.save_as(&self.path)
    }

    /// Writes the store to an arbitrary path (used to mirror a shared store to
    /// both its cache and the shared file).
    pub fn save_as(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let file = StoreFile {
            description: self.description.clone(),
            icon: self.icon.clone(),
            color: self.color,
            name: self.name.clone(),
            id: self.id.clone(),
            sessions: self.sessions.clone(),
            folders: self.folders.clone(),
            folder_styles: self.folder_styles.clone(),
            folder_meta: self.folder_meta.clone(),
        };
        let text = toml::to_string_pretty(&file).context("could not serialize sessions")?;
        write_atomic(path, text.as_bytes())
            .with_context(|| format!("could not write {}", path.display()))
    }
}

/// A 16-character random hex id.
fn new_id() -> String {
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("toml.tmp");
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

    #[test]
    fn new_session_defaults() {
        let s = Session::new("prod", "example.com", "root");
        assert_eq!(s.port, 22);
        assert_eq!(s.auth, Auth::Prompt);
        assert_eq!(s.address(), "root@example.com");
        assert_eq!(s.id.len(), 16);
    }

    #[test]
    fn legacy_auth_migrates_on_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.toml");
        // Hand-write a file using the old auth variants.
        let toml = r#"
[[session]]
id = "aaaaaaaaaaaaaaaa"
name = "agent one"
host = "h"
username = "u"
[session.auth]
method = "agent"

[[session]]
id = "bbbbbbbbbbbbbbbb"
name = "pw one"
host = "h"
username = "u"
[session.auth]
method = "password"
secret = "prod-db"

[[session]]
id = "cccccccccccccccc"
name = "pw prompt"
host = "h"
username = "u"
[session.auth]
method = "password"
secret = ""

[[session]]
id = "dddddddddddddddd"
name = "key one"
host = "h"
username = "u"
[session.auth]
method = "key"
secret = "deploy-key"
"#;
        fs::write(&path, toml).unwrap();
        let store = SessionStore::load(path.clone()).unwrap();
        assert_eq!(store.get("aaaaaaaaaaaaaaaa").unwrap().auth, Auth::Prompt);
        assert_eq!(
            store.get("bbbbbbbbbbbbbbbb").unwrap().auth,
            Auth::Vault { entry: "prod-db".into() }
        );
        assert_eq!(store.get("cccccccccccccccc").unwrap().auth, Auth::Prompt);
        assert_eq!(
            store.get("dddddddddddddddd").unwrap().auth,
            Auth::Vault { entry: "deploy-key".into() }
        );

        // The file was rewritten in the new format and no longer migrates.
        let reloaded = SessionStore::load(path).unwrap();
        assert_eq!(
            reloaded.get("dddddddddddddddd").unwrap().auth,
            Auth::Vault { entry: "deploy-key".into() }
        );
    }

    #[test]
    fn appearance_persists_in_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.toml");
        let mut store = SessionStore::load(path.clone()).unwrap();
        assert_eq!(store.icon(), "");
        assert_eq!(store.color(), None);

        store.set_appearance("🌐", Some([10, 20, 30])).unwrap();
        store.set_description("Team").unwrap();

        // Icon, color and description all survive a reload from the file.
        let reloaded = SessionStore::load(path).unwrap();
        assert_eq!(reloaded.icon(), "🌐");
        assert_eq!(reloaded.color(), Some([10, 20, 30]));
        assert_eq!(reloaded.description(), "Team");
    }

    #[test]
    fn address_includes_nondefault_port() {
        let mut s = Session::new("x", "h", "u");
        s.port = 2222;
        assert_eq!(s.address(), "u@h:2222");
    }

    #[test]
    fn upsert_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.toml");

        let mut store = SessionStore::load(path.clone()).unwrap();
        let mut s = Session::new("prod", "example.com", "root");
        s.folder = "work".into();
        s.auth = Auth::Vault { entry: "deploy-key".into() };
        let id = s.id.clone();
        store.upsert(s).unwrap();

        let reloaded = SessionStore::load(path).unwrap();
        assert_eq!(reloaded.all().len(), 1);
        let got = reloaded.get(&id).unwrap();
        assert_eq!(got.folder, "work");
        assert_eq!(got.auth, Auth::Vault { entry: "deploy-key".into() });
    }

    #[test]
    fn upsert_replaces_by_id() {
        let dir = tempdir().unwrap();
        let mut store = SessionStore::load(dir.path().join("s.toml")).unwrap();
        let mut s = Session::new("a", "h", "u");
        store.upsert(s.clone()).unwrap();
        s.name = "renamed".into();
        store.upsert(s.clone()).unwrap();
        assert_eq!(store.all().len(), 1);
        assert_eq!(store.get(&s.id).unwrap().name, "renamed");
    }

    #[test]
    fn remove_session() {
        let dir = tempdir().unwrap();
        let mut store = SessionStore::load(dir.path().join("s.toml")).unwrap();
        let s = Session::new("a", "h", "u");
        let id = s.id.clone();
        store.upsert(s).unwrap();
        assert!(store.remove(&id).unwrap());
        assert!(!store.remove(&id).unwrap());
        assert!(store.all().is_empty());
    }

    #[test]
    fn missing_file_is_empty_store() {
        let dir = tempdir().unwrap();
        let store = SessionStore::load(dir.path().join("nope.toml")).unwrap();
        assert!(store.all().is_empty());
    }

    #[test]
    fn folder_crud() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("s.toml");
        let mut store = SessionStore::load(path.clone()).unwrap();
        assert!(store.add_folder("work").unwrap());
        assert!(!store.add_folder("work").unwrap()); // idempotent
        let mut s = Session::new("a", "h", "u");
        s.folder = "work".into();
        let id = s.id.clone();
        store.upsert(s).unwrap();
        assert!(store.folders().contains(&"work".to_string()));

        store.rename_folder("work", "prod").unwrap();
        assert_eq!(store.get(&id).unwrap().folder, "prod");

        store.move_to_folder(&id, "").unwrap();
        assert_eq!(store.get(&id).unwrap().folder, "");

        store.add_folder("empty").unwrap();
        store.remove_folder("empty").unwrap();
        assert!(!store.folders().contains(&"empty".to_string()));

        // Folders persist across reload.
        let reloaded = SessionStore::load(path).unwrap();
        assert!(reloaded.folders().contains(&"prod".to_string()));
    }

    #[test]
    fn nested_folder_rename_and_remove() {
        let dir = tempdir().unwrap();
        let mut store = SessionStore::load(dir.path().join("s.toml")).unwrap();
        store.add_folder("work/prod").unwrap();
        let mut s = Session::new("db", "h", "u");
        s.folder = "work/prod".into();
        let id = s.id.clone();
        store.upsert(s).unwrap();

        // Renaming a parent re-paths its descendants.
        store.rename_folder("work", "ops").unwrap();
        assert_eq!(store.get(&id).unwrap().folder, "ops/prod");
        assert!(store.folders().contains(&"ops/prod".to_string()));

        // Removing a parent clears sessions in its subtree.
        store.remove_folder("ops").unwrap();
        assert_eq!(store.get(&id).unwrap().folder, "");
        assert!(store.folders().is_empty());
    }

    #[test]
    fn grouping_by_folder() {
        let dir = tempdir().unwrap();
        let mut store = SessionStore::load(dir.path().join("s.toml")).unwrap();
        let mut a = Session::new("a", "h", "u");
        a.folder = "work".into();
        let b = Session::new("b", "h", "u"); // root
        store.upsert(a).unwrap();
        store.upsert(b).unwrap();
        let groups = store.by_folder();
        assert_eq!(groups[""].len(), 1);
        assert_eq!(groups["work"].len(), 1);
    }
}
