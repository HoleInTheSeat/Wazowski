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
    /// Authenticate from a named vault entry: a password entry is used as the
    /// HTTPS token (+username), an SSH keypair entry as the SSH key.
    Vault,
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
    /// Name of the vault entry to authenticate with (for `GitAuthKind::Vault`).
    #[serde(default)]
    pub vault_entry: String,
    /// Optional custom icon (an emoji); empty uses the default.
    #[serde(default)]
    pub icon: String,
    /// Optional custom header color, as sRGB `[r, g, b]`.
    #[serde(default)]
    pub color: Option<[u8; 3]>,
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

    /// Records bytes locally without publishing to the remote. For a folder share
    /// this writes the file directly (there is nothing to push); for git it
    /// commits locally, leaving the commit to be pushed later via [`push`].
    fn commit(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Backend::Folder(path) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, bytes).map_err(Into::into)
            }
            Backend::Git(repo) => repo.commit(bytes),
        }
    }

    /// Publishes bytes to the share immediately (folder write / git commit+push).
    fn publish(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Backend::Folder(_) => self.commit(bytes),
            Backend::Git(repo) => repo.publish(bytes),
        }
    }

    /// Pushes locally-committed changes. A folder share has nothing to push.
    fn push(&self) -> Result<()> {
        match self {
            Backend::Folder(_) => Ok(()),
            Backend::Git(repo) => repo.push(),
        }
    }

    /// Whether there are local changes not yet on the remote (git only).
    fn has_pending(&self) -> bool {
        match self {
            Backend::Folder(_) => false,
            Backend::Git(repo) => repo.has_unpushed().unwrap_or(false),
        }
    }

    /// Discards local changes, matching the remote (git only).
    fn discard(&self) -> Result<()> {
        match self {
            Backend::Folder(_) => Ok(()),
            Backend::Git(repo) => repo.discard(),
        }
    }
}

/// Builds the backend for a source definition. `vault_auth` is the auth resolved
/// from the vault by the caller (only used when the source's auth is
/// `GitAuthKind::Vault`); it's `None` when the vault is locked or unavailable.
fn backend_for(def: &SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Backend {
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
                    inline_key: None,
                },
                // The caller resolves the vault entry (it has the unlocked vault);
                // a locked vault yields `None`, so the source stays offline until
                // it's unlocked and the source re-opened.
                GitAuthKind::Vault => vault_auth.unwrap_or(GitAuth::None),
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

    /// Replaces an existing source definition (matched by id), or appends it.
    pub fn update(&mut self, def: SourceDef) -> Result<()> {
        match self.defs.iter_mut().find(|d| d.id == def.id) {
            Some(existing) => *existing = def,
            None => self.defs.push(def),
        }
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
    pub fn open(def: SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Self {
        let cache_path = cache_dir.join(format!("{}.toml", def.id));
        let backend = backend_for(&def, cache_dir, vault_auth);
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
                log::warn!(
                    "shared source \"{}\" ({}) could not sync: {e:#}",
                    self.def.name,
                    match self.def.kind {
                        SourceKind::Folder => "folder",
                        SourceKind::Git => "git",
                    }
                );
                self.status = Some(format!("share offline ({e}) — using local cache (read-only)"));
            }
        }
        self.store = SessionStore::load(self.cache_path.clone()).unwrap_or_default();
    }

    /// Saves the store to the cache and returns its bytes.
    fn cache_bytes(&self) -> Result<Vec<u8>> {
        self.store
            .save_as(&self.cache_path)
            .context("could not update the local cache")?;
        fs::read(&self.cache_path).context("reading cache")
    }

    /// Records a store change: writes the cache and commits it locally. For git
    /// this does not push — the change becomes "pending" until [`push`] or a sync
    /// sends it. For a folder share, committing writes the file directly.
    fn write_through(&mut self) -> Result<()> {
        let bytes = self.cache_bytes()?;
        self.backend.commit(&bytes)?;
        self.available = true;
        self.missing = false;
        self.status = None;
        Ok(())
    }

    /// This source's free-text description (stored in the shared file, so it
    /// travels with the sessions and every user sees it). Empty if none.
    pub fn description(&self) -> &str {
        self.store.description()
    }

    /// Sets the description in the shared file (write-through to the share).
    pub fn set_description(&mut self, description: &str) -> Result<()> {
        self.mutate(|s| s.set_description(description))
    }

    /// Sets the description in the in-memory store only, to be persisted by the
    /// next `create()` — used when first creating a brand-new source's file.
    pub fn prime_description(&mut self, description: &str) {
        let _ = self.store.set_description(description);
    }

    /// Whether there are local changes not yet pushed to the remote (git only).
    pub fn has_pending(&self) -> bool {
        self.backend.has_pending()
    }

    /// Pushes locally-committed changes to the remote.
    pub fn push(&mut self) -> Result<()> {
        self.backend.push()?;
        self.available = true;
        self.missing = false;
        self.status = None;
        Ok(())
    }

    /// Discards local (unpushed) changes, resetting to the remote, then reloads.
    pub fn discard(&mut self) -> Result<()> {
        self.backend.discard()?;
        self.reload();
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

    /// (Re)creates the shared file from the current cache contents, publishing it
    /// immediately (this is a deliberate setup action, so it pushes right away).
    pub fn create(&mut self) -> Result<()> {
        let bytes = self.cache_bytes()?;
        self.backend.publish(&bytes)?;
        self.available = true;
        self.missing = false;
        self.status = None;
        Ok(())
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

    pub fn set_folder_style(
        &mut self,
        folder: &str,
        style: wazowski_core::FolderStyle,
    ) -> Result<()> {
        self.mutate(|s| s.set_folder_style(folder, style))
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
            vault_entry: String::new(),
            icon: String::new(),
            color: None,
        };

        // A brand-new source has no file yet; create() writes an empty one.
        let mut source = SharedSource::open(def.clone(), &cache, None);
        assert!(!source.available());
        source.create().unwrap();
        assert!(source.available());
        source.upsert(Session::new("web", "example.com", "root")).unwrap();
        source.set_description("Team servers").unwrap();
        assert!(share.exists(), "share file should be written");
        assert_eq!(source.store().all().len(), 1);

        // Reopen from the share: the description is stored in the file, so it and
        // the session both come back.
        let reopened = SharedSource::open(def.clone(), &cache, None);
        assert_eq!(reopened.description(), "Team servers", "description persists in the file");
        assert_eq!(reopened.store().all().len(), 1);

        // Reopen from cache with the share removed: session still present, offline.
        fs::remove_dir_all(dir.path().join("share")).unwrap();
        let offline = SharedSource::open(def, &cache, None);
        assert!(!offline.available());
        assert_eq!(offline.store().all().len(), 1, "cache keeps sessions when offline");
        assert_eq!(offline.description(), "Team servers", "description available offline too");
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
            vault_entry: String::new(),
            icon: String::new(),
            color: None,
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
            vault_entry: String::new(),
            icon: String::new(),
            color: None,
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
        let mut a = SharedSource::open(git_def("g1", &url), &cache_a, None);
        assert!(!a.available() && a.missing());
        a.create().unwrap();
        a.upsert(Session::new("web", "example.com", "root")).unwrap();
        assert!(a.available());
        // Mutations now commit locally without pushing, so the change is pending
        // until an explicit push.
        assert!(a.has_pending(), "the local commit should be pending a push");
        a.push().unwrap();
        assert!(!a.has_pending(), "pushing clears the pending state");

        // A second clone of the same remote sees the pushed session.
        let cache_b = dir.path().join("cache-b");
        let b = SharedSource::open(git_def("g2", &url), &cache_b, None);
        assert!(b.available(), "second clone should be online: {:?}", b.status());
        assert_eq!(b.store().all().len(), 1, "pushed session should sync via git");
    }

    // Two sources sharing one repo (different files) must both be able to push:
    // the second push integrates the first (rebase) instead of being rejected as
    // non-fast-forward. Regression test for the "second source fails to push
    // until relaunch" bug.
    #[test]
    #[ignore = "requires the git binary"]
    fn two_sources_same_repo_can_both_push() {
        use std::process::Command;
        let dir = tempdir().unwrap();
        let remote = dir.path().join("remote.git");
        assert!(
            Command::new("git")
                .args(["init", "--bare", "-b", "main"])
                .arg(&remote)
                .status()
                .unwrap()
                .success()
        );
        let url = remote.to_string_lossy().into_owned();
        let def_file = |id: &str, file: &str| {
            let mut d = git_def(id, &url);
            d.file = file.into();
            d
        };

        // Source A seeds a.toml; source B seeds b.toml in the same repo.
        let mut a = SharedSource::open(def_file("a", "a.toml"), &dir.path().join("a"), None);
        a.create().unwrap();
        let mut b = SharedSource::open(def_file("b", "b.toml"), &dir.path().join("b"), None);
        b.create().unwrap();

        // A pushes a change; now B's clone is behind the shared branch.
        a.upsert(Session::new("hostA", "a.example.com", "root")).unwrap();
        a.push().unwrap();

        // B edits its own file and pushes — must succeed by integrating A's commit,
        // not fail as non-fast-forward.
        b.upsert(Session::new("hostB", "b.example.com", "root")).unwrap();
        b.push().unwrap();
        assert!(!b.has_pending(), "B's push should clear its pending state");

        // A fresh clone of each file sees the expected sessions.
        let ca = SharedSource::open(def_file("ca", "a.toml"), &dir.path().join("ca"), None);
        let cb = SharedSource::open(def_file("cb", "b.toml"), &dir.path().join("cb"), None);
        assert_eq!(ca.store().all().len(), 1, "A's session survived B's push");
        assert_eq!(cb.store().all().len(), 1, "B's session was pushed");
    }
}
