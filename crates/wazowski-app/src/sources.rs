//! Shared session sources.
//!
//! A shared source is a sessions file living on a shared or synced location (a
//! network mount, NAS, Dropbox/Nextcloud folder, …). Wazowski mirrors it to a
//! local cache so the sessions stay available when the share is offline, and
//! writes through to the share when it is reachable. No secrets are stored in a
//! share — sessions reference vault entries by name, created locally on first use.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use wazowski_core::{Session, SessionStore};

use crate::git::{GitAuth, GitRepo};

/// Whether a source is a shared file/folder or a git repo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    #[default]
    Folder,
    Git,
}

/// Git authentication choice (the token itself lives in the OS keyring).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitAuthKind {
    #[default]
    None,
    Https,
    Ssh,
}

fn default_file() -> String {
    "wazowski-sessions.toml".to_owned()
}

/// A configured shared source (persisted in `sources.toml`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceDef {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: SourceKind,
    /// Path to the shared sessions file (folder kind).
    #[serde(default)]
    pub path: PathBuf,
    /// Repository URL (git kind).
    #[serde(default)]
    pub url: String,
    /// Branch to track; empty means the remote default.
    #[serde(default)]
    pub branch: String,
    /// Sessions-file path within the repo.
    #[serde(default = "default_file")]
    pub file: String,
    #[serde(default)]
    pub auth: GitAuthKind,
    /// Git HTTPS username (token is in the keyring).
    #[serde(default)]
    pub username: String,
    /// Git SSH private key path (empty = agent/default key).
    #[serde(default)]
    pub key_path: String,
}

/// The keyring service under which git HTTPS tokens are stored.
const GIT_TOKEN_SERVICE: &str = "org.wazowski.git-token";

/// Stores a git HTTPS token for a source in the OS keyring.
pub fn store_git_token(id: &str, token: &str) -> Result<()> {
    keyring::Entry::new(GIT_TOKEN_SERVICE, id)
        .context("the OS keyring is unavailable")?
        .set_password(token)
        .context("could not store the token")
}

/// Loads a source's git HTTPS token from the keyring, if any.
pub fn load_git_token(id: &str) -> Option<String> {
    keyring::Entry::new(GIT_TOKEN_SERVICE, id).ok()?.get_password().ok()
}

/// Removes a source's git token from the keyring.
pub fn delete_git_token(id: &str) {
    if let Ok(entry) = keyring::Entry::new(GIT_TOKEN_SERVICE, id) {
        let _ = entry.delete_credential();
    }
}

/// How a source reaches its shared sessions file.
enum Backend {
    /// A file on a shared/synced path.
    Folder(PathBuf),
    /// A git working clone.
    Git(GitRepo),
}

impl Backend {
    /// Reads the current shared bytes (`None` if the file doesn't exist there).
    fn fetch(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Backend::Folder(path) => match fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            },
            Backend::Git(repo) => repo.fetch(),
        }
    }

    /// Publishes bytes to the share.
    fn publish(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Backend::Folder(path) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, bytes).map_err(Into::into)
            }
            Backend::Git(repo) => repo.publish(bytes),
        }
    }
}

/// Builds the backend for a source definition.
fn backend_for(def: &SourceDef, cache_dir: &Path) -> Backend {
    match def.kind {
        SourceKind::Folder => Backend::Folder(def.path.clone()),
        SourceKind::Git => {
            let auth = match def.auth {
                GitAuthKind::None => GitAuth::None,
                GitAuthKind::Https => GitAuth::Https {
                    username: def.username.clone(),
                    token: load_git_token(&def.id).unwrap_or_default(),
                },
                GitAuthKind::Ssh => GitAuth::Ssh {
                    key_path: (!def.key_path.is_empty()).then(|| PathBuf::from(&def.key_path)),
                },
            };
            let work_dir = cache_dir.join("git").join(&def.id);
            Backend::Git(GitRepo::new(
                work_dir,
                def.url.clone(),
                def.branch.clone(),
                def.file.clone(),
                auth,
            ))
        }
    }
}

/// The persisted list of shared sources.
#[derive(Default, Serialize, Deserialize)]
struct SourcesFile {
    #[serde(default, rename = "source")]
    sources: Vec<SourceDef>,
}

/// Loads/saves the list of configured sources.
pub struct SourcesConfig {
    path: PathBuf,
    pub defs: Vec<SourceDef>,
}

impl SourcesConfig {
    /// `~/.config/wazowski/sources.toml`.
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("sources.toml"))
    }

    pub fn load(path: PathBuf) -> Result<Self> {
        let defs = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<SourcesFile>(&text)
                .with_context(|| format!("could not parse {}", path.display()))?
                .sources,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        Ok(Self { path, defs })
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = SourcesFile { sources: self.defs.clone() };
        let text = toml::to_string_pretty(&file).context("could not serialize sources")?;
        fs::write(&self.path, text).with_context(|| format!("could not write {}", self.path.display()))
    }

    pub fn add(&mut self, def: SourceDef) -> Result<()> {
        self.defs.push(def);
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.defs.retain(|d| d.id != id);
        self.save()
    }
}

/// A live shared source: its definition plus an in-memory store backed by a
/// local cache, kept in sync with the shared file when it is reachable.
pub struct SharedSource {
    def: SourceDef,
    cache_path: PathBuf,
    backend: Backend,
    store: SessionStore,
    /// Whether the share was reachable at the last load/sync.
    available: bool,
    /// Whether the last failure was specifically "file not found".
    missing: bool,
    /// A note about the last sync problem, for display.
    status: Option<String>,
}

impl SharedSource {
    /// Opens a source: refresh the cache from the share if reachable, then load
    /// the store from the cache (so it works offline).
    pub fn open(def: SourceDef, cache_dir: &Path) -> Self {
        let cache_path = cache_dir.join(format!("{}.toml", def.id));
        let backend = backend_for(&def, cache_dir);
        let mut source = Self {
            def,
            cache_path,
            backend,
            store: SessionStore::default(),
            available: false,
            missing: false,
            status: None,
        };
        source.reload();
        source
    }

    /// Re-reads the share (refreshing the cache) and reloads the store.
    pub fn reload(&mut self) {
        if let Some(parent) = self.cache_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match self.backend.fetch() {
            Ok(Some(bytes)) => {
                if let Err(e) = fs::write(&self.cache_path, &bytes) {
                    self.status = Some(format!("could not update cache: {e}"));
                }
                self.available = true;
                self.missing = false;
                self.status = None;
            }
            Ok(None) => {
                // Reachable, but the sessions file doesn't exist yet.
                self.available = false;
                self.missing = true;
                self.status = Some("shared file not found — using local cache (read-only)".into());
            }
            Err(e) => {
                self.available = false;
                self.missing = false;
                self.status = Some(format!("share offline ({e}) — using local cache (read-only)"));
            }
        }
        self.store = SessionStore::load(self.cache_path.clone()).unwrap_or_default();
    }

    /// Writes the current store to the share (and refreshes the cache).
    fn write_through(&mut self) -> Result<()> {
        self.store
            .save_as(&self.cache_path)
            .context("could not update the local cache")?;
        let bytes = fs::read(&self.cache_path).context("reading cache")?;
        self.backend.publish(&bytes)?;
        self.available = true;
        self.missing = false;
        self.status = None;
        Ok(())
    }

    /// Applies a store mutation, then writes through to the share. Mutations are
    /// refused while the share is offline, to avoid conflicting with it.
    fn mutate(&mut self, f: impl FnOnce(&mut SessionStore) -> Result<()>) -> Result<()> {
        if !self.available {
            anyhow::bail!("the shared source is offline; changes are disabled");
        }
        f(&mut self.store)?;
        self.write_through()
    }

    /// (Re)creates the shared file from the current cache contents.
    pub fn create(&mut self) -> Result<()> {
        self.write_through()
    }

    /// Whether the shared file is specifically missing (vs the location offline).
    pub fn missing(&self) -> bool {
        self.missing
    }

    /// Whether the missing share can be recreated from the local cache. True only
    /// for a folder source whose file is gone (a deleted git repo can't be remade).
    pub fn can_recreate(&self) -> bool {
        self.missing && matches!(self.backend, Backend::Folder(_))
    }

    // --- Accessors -------------------------------------------------------

    pub fn id(&self) -> &str {
        &self.def.id
    }

    pub fn name(&self) -> &str {
        &self.def.name
    }

    pub fn store(&self) -> &SessionStore {
        &self.store
    }

    pub fn def(&self) -> &SourceDef {
        &self.def
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    // --- Mutations (write-through to the share) --------------------------

    pub fn upsert(&mut self, session: Session) -> Result<()> {
        self.mutate(|s| s.upsert(session))
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.mutate(|s| s.remove(id).map(|_| ()))
    }

    pub fn add_folder(&mut self, name: &str) -> Result<()> {
        self.mutate(|s| s.add_folder(name).map(|_| ()))
    }

    pub fn remove_folder(&mut self, name: &str) -> Result<()> {
        self.mutate(|s| s.remove_folder(name))
    }

    pub fn rename_folder(&mut self, old: &str, new: &str) -> Result<()> {
        self.mutate(|s| s.rename_folder(old, new))
    }

    pub fn move_to_folder(&mut self, id: &str, folder: &str) -> Result<()> {
        self.mutate(|s| s.move_to_folder(id, folder))
    }
}

/// Opens a source's location: the folder containing its file (folder kind) or
/// the repository in a web browser (git kind).
pub fn open_source(def: &SourceDef) -> Result<()> {
    match def.kind {
        SourceKind::Folder => {
            // Show the file's directory in the file manager.
            let target = def.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(&def.path);
            open::that_detached(target).context("could not open the file location")
        }
        SourceKind::Git => {
            let url = git_web_url(&def.url)
                .ok_or_else(|| anyhow::anyhow!("don't know how to open '{}' in a browser", def.url))?;
            open::that_detached(url).context("could not open the browser")
        }
    }
}

/// Converts a git remote URL into a browsable web URL.
/// Handles `git@host:group/repo(.git)`, `ssh://git@host/group/repo(.git)`, and
/// `https://host/group/repo(.git)`.
fn git_web_url(url: &str) -> Option<String> {
    let url = url.trim();
    let strip_git = |s: &str| s.strip_suffix(".git").unwrap_or(s).to_owned();

    if let Some(rest) = url.strip_prefix("git@") {
        // git@host:group/repo.git -> https://host/group/repo
        let (host, path) = rest.split_once(':')?;
        return Some(format!("https://{host}/{}", strip_git(path)));
    }
    if let Some(rest) = url.strip_prefix("ssh://") {
        // ssh://git@host[:port]/group/repo.git
        let rest = rest.split_once('@').map(|(_, r)| r).unwrap_or(rest);
        let (host, path) = rest.split_once('/')?;
        let host = host.split(':').next().unwrap_or(host); // drop any port
        return Some(format!("https://{host}/{}", strip_git(path)));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(strip_git(url));
    }
    None
}

/// The local-data cache directory for shared sources.
pub fn cache_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
        .context("could not determine a data directory")?;
    Ok(dirs.data_dir().join("shared-cache"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_through_and_cache_fallback() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("share")).unwrap();
        let share = dir.path().join("share/team.toml");
        let cache = dir.path().join("cache");
        let def = SourceDef {
            id: "t1".into(),
            name: "Team".into(),
            kind: SourceKind::Folder,
            path: share.clone(),
            url: String::new(),
            branch: String::new(),
            file: default_file(),
            auth: GitAuthKind::None,
            username: String::new(),
            key_path: String::new(),
        };

        // A brand-new source has no file yet; create() writes an empty one.
        let mut source = SharedSource::open(def.clone(), &cache);
        assert!(!source.available());
        source.create().unwrap();
        assert!(source.available());
        source.upsert(Session::new("web", "example.com", "root")).unwrap();
        assert!(share.exists(), "share file should be written");
        assert_eq!(source.store().all().len(), 1);

        // Reopen from cache with the share removed: session still present, offline.
        fs::remove_dir_all(dir.path().join("share")).unwrap();
        let offline = SharedSource::open(def, &cache);
        assert!(!offline.available());
        assert_eq!(offline.store().all().len(), 1, "cache keeps sessions when offline");
    }

    #[test]
    fn config_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sources.toml");
        let mut cfg = SourcesConfig::load(path.clone()).unwrap();
        cfg.add(SourceDef {
            id: "a".into(),
            name: "A".into(),
            kind: SourceKind::Folder,
            path: "/x/a.toml".into(),
            url: String::new(),
            branch: String::new(),
            file: default_file(),
            auth: GitAuthKind::None,
            username: String::new(),
            key_path: String::new(),
        })
        .unwrap();
        let reloaded = SourcesConfig::load(path).unwrap();
        assert_eq!(reloaded.defs.len(), 1);
        assert_eq!(reloaded.defs[0].name, "A");
    }

    fn git_def(id: &str, url: &str) -> SourceDef {
        SourceDef {
            id: id.into(),
            name: "Git".into(),
            kind: SourceKind::Git,
            path: PathBuf::new(),
            url: url.into(),
            branch: "main".into(),
            file: "sessions.toml".into(),
            auth: GitAuthKind::None,
            username: String::new(),
            key_path: String::new(),
        }
    }

    #[test]
    fn git_web_url_conversion() {
        assert_eq!(
            git_web_url("git@github.com:HoleInTheSeat/sharesessiontest.git").as_deref(),
            Some("https://github.com/HoleInTheSeat/sharesessiontest")
        );
        assert_eq!(
            git_web_url("https://gitlab.com/group/repo.git").as_deref(),
            Some("https://gitlab.com/group/repo")
        );
        assert_eq!(
            git_web_url("ssh://git@forgejo.example.com:2222/team/sessions.git").as_deref(),
            Some("https://forgejo.example.com/team/sessions")
        );
        assert_eq!(git_web_url("not a url"), None);
    }

    // Uses the real `git` binary against a local bare repo (no network/auth).
    #[test]
    #[ignore = "requires the git binary"]
    fn git_backend_round_trip() {
        use std::process::Command;
        let dir = tempdir().unwrap();
        let remote = dir.path().join("remote.git");
        let ok = Command::new("git")
            .args(["init", "--bare", "-b", "main"])
            .arg(&remote)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git init --bare failed");
        let url = remote.to_string_lossy().into_owned();

        // First clone: empty repo, so the file is missing until we create it.
        let cache_a = dir.path().join("cache-a");
        let mut a = SharedSource::open(git_def("g1", &url), &cache_a);
        assert!(!a.available() && a.missing());
        a.create().unwrap();
        a.upsert(Session::new("web", "example.com", "root")).unwrap();
        assert!(a.available());

        // A second clone of the same remote sees the pushed session.
        let cache_b = dir.path().join("cache-b");
        let b = SharedSource::open(git_def("g2", &url), &cache_b);
        assert!(b.available(), "second clone should be online: {:?}", b.status());
        assert_eq!(b.store().all().len(), 1, "pushed session should sync via git");
    }
}
