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

/// How a session authenticates to the remote host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Auth {
    /// Use keys already loaded in the running SSH agent.
    #[default]
    Agent,
    /// A password stored in the vault under this secret name.
    Password { secret: String },
    /// A private key stored in the vault under this secret name.
    Key { secret: String },
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
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub auth: Auth,
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
            host: host.into(),
            port: default_port(),
            username: username.into(),
            auth: Auth::default(),
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

/// An in-memory collection of sessions backed by a TOML file.
#[derive(Debug, Default)]
pub struct SessionStore {
    path: PathBuf,
    sessions: Vec<Session>,
}

/// The serialized file shape: `[[session]]` tables.
#[derive(Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default, rename = "session")]
    sessions: Vec<Session>,
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
        let sessions = match fs::read_to_string(&path) {
            Ok(text) => {
                let file: StoreFile = toml::from_str(&text)
                    .with_context(|| format!("could not parse {}", path.display()))?;
                file.sessions
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        Ok(Self { path, sessions })
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

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let file = StoreFile { sessions: self.sessions.clone() };
        let text = toml::to_string_pretty(&file).context("could not serialize sessions")?;
        write_atomic(&self.path, text.as_bytes())
            .with_context(|| format!("could not write {}", self.path.display()))
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
        assert_eq!(s.auth, Auth::Agent);
        assert_eq!(s.address(), "root@example.com");
        assert_eq!(s.id.len(), 16);
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
        s.auth = Auth::Key { secret: "deploy-key".into() };
        let id = s.id.clone();
        store.upsert(s).unwrap();

        let reloaded = SessionStore::load(path).unwrap();
        assert_eq!(reloaded.all().len(), 1);
        let got = reloaded.get(&id).unwrap();
        assert_eq!(got.folder, "work");
        assert_eq!(got.auth, Auth::Key { secret: "deploy-key".into() });
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
