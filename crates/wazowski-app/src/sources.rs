//! Shared session sources.
//!
//! A shared source is a sessions file living on a shared or synced location (a
//! network mount, NAS, Dropbox/Nextcloud folder, …). Wazowski mirrors it to a
//! local cache so the sessions stay available when the share is offline, and
//! writes through to the share when it is reachable. No secrets are stored in a
//! share — sessions reference vault entries by name, created locally on first use.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use wazowski_core::{Session, SessionStore, tree};

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

/// Renders a folder path (`work/prod`) with a folder emoji between segments, so
/// the hierarchy reads top-down in the git log: `work 📂 prod`. Empty for the
/// root. Used to build descriptive git commit messages for shared sources.
fn folder_breadcrumb(folder: &str) -> String {
    folder.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" 📂 ")
}

/// A session's name, a `|` divider, then the folder path that contains it, e.g.
/// `Switches | DataCenter 📂 z_Tech Office 📂 Deven's Desk` (just the name at root).
fn session_location(folder: &str, name: &str) -> String {
    let crumb = folder_breadcrumb(folder);
    if crumb.is_empty() { name.to_owned() } else { format!("{name} | {crumb}") }
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

/// Outcome of refreshing the local working tree from the remote.
enum FetchOutcome {
    /// A session tree is present (and now mirrored locally).
    Present,
    /// The remote is reachable but holds no tree yet (fresh repo / missing dir).
    Missing,
}

/// How a source reaches its shared session tree. The shared store is laid out as
/// a directory tree (see [`wazowski_core::tree`]); each backend keeps a local
/// working copy of it under the cache, which is what the store is assembled from.
enum Backend {
    /// A tree directory on a shared/synced path (`share`), mirrored locally
    /// (`work`) so it stays available offline.
    Folder { share: PathBuf, work: PathBuf },
    /// A git working clone (boxed: much larger than the folder variant). The tree
    /// lives at the clone's root.
    Git(Box<GitRepo>),
}

impl Backend {
    /// The local working-tree directory the store is assembled from.
    fn work_dir(&self) -> &Path {
        match self {
            Backend::Folder { work, .. } => work,
            Backend::Git(repo) => repo.work_dir(),
        }
    }

    /// Refreshes the local working tree from the remote. `Err` means the remote
    /// was unreachable (go offline, keep the cached tree).
    fn fetch(&self) -> Result<FetchOutcome> {
        match self {
            Backend::Folder { share, work } => match fs::metadata(share) {
                Ok(_) => {
                    tree::copy_tree(share, work).context("mirroring the shared location")?;
                    Ok(if tree::tree_present(work) {
                        FetchOutcome::Present
                    } else {
                        FetchOutcome::Missing
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FetchOutcome::Missing),
                Err(e) => Err(e).context("reading the shared location"),
            },
            Backend::Git(repo) => {
                Ok(if repo.fetch()? { FetchOutcome::Present } else { FetchOutcome::Missing })
            }
        }
    }

    /// Records the (already-written) working tree locally without publishing to
    /// the remote. For a folder share this mirrors the tree onto the share (there
    /// is nothing to push); for git it commits locally, to be pushed later via
    /// [`push`]. `message` is the commit subject (git only).
    fn commit(&self, message: &str) -> Result<()> {
        match self {
            Backend::Folder { share, work } => {
                tree::copy_tree(work, share).context("could not write to the shared location")
            }
            Backend::Git(repo) => repo.commit(message),
        }
    }

    /// Publishes the working tree to the share immediately (folder mirror / git
    /// commit+push).
    fn publish(&self, message: &str) -> Result<()> {
        match self {
            Backend::Folder { .. } => self.commit(message),
            Backend::Git(repo) => repo.publish(message),
        }
    }

    /// Pushes locally-committed changes. A folder share has nothing to push.
    fn push(&self) -> Result<()> {
        match self {
            Backend::Folder { .. } => Ok(()),
            Backend::Git(repo) => repo.push(),
        }
    }

    /// Whether there are local changes not yet on the remote (git only).
    fn has_pending(&self) -> bool {
        match self {
            Backend::Folder { .. } => false,
            Backend::Git(repo) => repo.has_unpushed().unwrap_or(false),
        }
    }

    /// Subjects of the commits a push would send (git only; empty for a folder).
    fn pending_commits(&self) -> Vec<String> {
        match self {
            Backend::Folder { .. } => Vec::new(),
            Backend::Git(repo) => repo.pending_commits(),
        }
    }

    /// Discards local changes, matching the remote (git reset / folder re-mirror).
    fn discard(&self) -> Result<()> {
        match self {
            Backend::Folder { share, work } => {
                tree::copy_tree(share, work).context("could not refresh from the shared location")
            }
            Backend::Git(repo) => repo.discard(),
        }
    }
}

/// Builds the backend for a source definition. `vault_auth` is the auth resolved
/// from the vault by the caller (only used when the source's auth is
/// `GitAuthKind::Vault`); it's `None` when the vault is locked or unavailable.
fn backend_for(def: &SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Backend {
    // One working-tree directory per source (the git clone, or the folder mirror).
    let work_dir = cache_dir.join(&def.id);
    match def.kind {
        SourceKind::Folder => Backend::Folder { share: def.path.clone(), work: work_dir },
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
            Backend::Git(Box::new(GitRepo::new(
                work_dir,
                def.url.clone(),
                def.branch.clone(),
                auth,
            )))
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

    pub fn save(&self) -> Result<()> {
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
    /// Shared (`Arc`) so a background refresh thread can run `fetch()` without
    /// blocking the UI, while the main thread keeps using it for commit/push.
    backend: Arc<Backend>,
    store: SessionStore,
    /// Whether the share was reachable at the last load/sync.
    available: bool,
    /// Whether the last failure was specifically "tree not found".
    missing: bool,
    /// A note about the last sync problem, for display.
    status: Option<String>,
    /// An in-flight background fetch, if any (its result applied by `poll_reload`).
    refresh: Option<Receiver<Result<FetchOutcome, String>>>,
}

impl SharedSource {
    /// Builds a source without touching the network/share. Assembles the store
    /// from the local working tree so sessions are available immediately (offline).
    fn from_cache(def: SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Self {
        let backend = Arc::new(backend_for(&def, cache_dir, vault_auth));
        let work = backend.work_dir();
        let available = tree::tree_present(work);
        let store = tree::assemble(work).unwrap_or_default();
        Self { def, backend, store, available, missing: false, status: None, refresh: None }
    }

    /// Opens a source synchronously: refresh the cache from the share (blocking),
    /// then load the store. Used by tests and by one-shot operations where a brief
    /// block is fine (creating/editing a source). The app's startup/sync paths use
    /// [`open_deferred`](Self::open_deferred) to avoid freezing the UI.
    pub fn open(def: SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Self {
        let mut source = Self::from_cache(def, cache_dir, vault_auth);
        source.reload();
        source
    }

    /// Opens a source without blocking: loads the local cache immediately, then
    /// kicks off a background refresh (see [`poll_reload`](Self::poll_reload)).
    pub fn open_deferred(def: SourceDef, cache_dir: &Path, vault_auth: Option<GitAuth>) -> Self {
        let mut source = Self::from_cache(def, cache_dir, vault_auth);
        source.begin_reload();
        source
    }

    /// Re-reads the share (refreshing the local working tree) and reloads the
    /// store. Blocking: a git source performs network I/O here. Prefer
    /// [`begin_reload`] on the UI.
    pub fn reload(&mut self) {
        let result = self.backend.fetch().map_err(|e| format!("{e:#}"));
        self.apply_fetch(result);
    }

    /// Starts a background refresh (no-op if one is already in flight). The fetch
    /// runs on a worker thread; call [`poll_reload`](Self::poll_reload) each frame
    /// to apply the result when it arrives.
    pub fn begin_reload(&mut self) {
        if self.refresh.is_some() {
            return;
        }
        let backend = Arc::clone(&self.backend);
        let (tx, rx) = mpsc::channel();
        // A detached worker: it owns a clone of the Arc'd backend and reports the
        // fetch result back. If the receiver is gone (source removed), the send
        // just fails harmlessly.
        std::thread::spawn(move || {
            let result = backend.fetch().map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
        });
        self.refresh = Some(rx);
    }

    /// Whether a background refresh is currently in flight.
    pub fn is_refreshing(&self) -> bool {
        self.refresh.is_some()
    }

    /// Applies a finished background refresh if one has landed. Returns `true`
    /// when state changed (so the caller can repaint). Cheap to call every frame.
    pub fn poll_reload(&mut self) -> bool {
        let Some(rx) = &self.refresh else { return false };
        match rx.try_recv() {
            Ok(result) => {
                self.refresh = None;
                self.apply_fetch(result);
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.refresh = None;
                true
            }
        }
    }

    /// Applies a fetch result (from a blocking or background fetch): updates the
    /// availability state, then re-assembles the store from the local working tree.
    fn apply_fetch(&mut self, result: Result<FetchOutcome, String>) {
        match result {
            Ok(FetchOutcome::Present) => {
                self.available = true;
                self.missing = false;
                self.status = None;
            }
            Ok(FetchOutcome::Missing) => {
                // Reachable, but the shared tree doesn't exist yet.
                self.available = false;
                self.missing = true;
                self.status = Some("shared tree not found — using local cache (read-only)".into());
            }
            Err(e) => {
                self.available = false;
                self.missing = false;
                log::warn!(
                    "shared source \"{}\" ({}) could not sync: {e}",
                    self.def.name,
                    match self.def.kind {
                        SourceKind::Folder => "folder",
                        SourceKind::Git => "git",
                    }
                );
                self.status = Some(format!("share offline ({e}) — using local cache (read-only)"));
            }
        }
        // One-time, idempotent upgrade of an old single-file layout to the tree.
        self.migrate_legacy();
        self.store = tree::assemble(self.backend.work_dir()).unwrap_or_default();
    }

    /// Converts a legacy single-file store in the working clone into the exploded
    /// tree, committing the change. A no-op once the tree exists (so it runs at
    /// most once), or when there's no legacy file (e.g. a fresh or folder source).
    ///
    /// Git repos clone every file, so the old `wazowski-sessions.toml` lands in the
    /// working clone and is found here; the migration commit is local (pending a
    /// push), so the first user to open the repo migrates it and everyone else
    /// pulls the tree. (Folder sources don't mirror non-tree files, so their
    /// migration is handled with the source-editor rework.)
    fn migrate_legacy(&mut self) {
        let work = self.backend.work_dir().to_path_buf();
        if tree::tree_present(&work) {
            return; // already the tree format (or an empty source)
        }
        let legacy = work.join(&self.def.file);
        if !legacy.is_file() {
            return; // nothing to migrate
        }
        // `SessionStore::load` normalizes legacy auth and drops inline usernames.
        let Ok(mut store) = SessionStore::load(legacy.clone()) else { return };
        store.ensure_ids();
        if tree::sync_tree(&store, &work).is_err() {
            return;
        }
        // Remove the old file so `git add -A` records its deletion in the migration
        // commit alongside the new tree.
        let _ = fs::remove_file(&legacy);
        if self.backend.commit("Migrate shared source to file-tree format").is_ok() {
            self.available = true;
            self.missing = false;
            self.status = None;
        }
    }

    /// Records a store change: writes the working tree and commits it locally. For
    /// git this does not push — the change becomes "pending" until [`push`] or a
    /// sync sends it. For a folder share, committing mirrors the tree onto the
    /// share. `message` becomes the git commit subject describing the change.
    fn write_through(&mut self, message: &str) -> Result<()> {
        self.store.ensure_ids();
        tree::sync_tree(&self.store, self.backend.work_dir())
            .context("could not update the local cache")?;
        self.backend.commit(message)?;
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
        self.mutate("Update source description", |s| s.set_description(description))
    }

    /// Sets the description in the in-memory store only, to be persisted by the
    /// next `create()` — used when first creating a brand-new source's file.
    pub fn prime_description(&mut self, description: &str) {
        let _ = self.store.set_description(description);
    }

    /// The source's effective header icon: the one stored in the shared file, or,
    /// if the file has none yet, the local `SourceDef` icon (so appearance set by
    /// an older build still shows and migrates into the file on the next save).
    pub fn display_icon(&self) -> &str {
        if self.store.icon().is_empty() { &self.def.icon } else { self.store.icon() }
    }

    /// The source's effective header color: the shared-file color, else the local
    /// `SourceDef` color (same migration fallback as [`display_icon`]).
    pub fn display_color(&self) -> Option<[u8; 3]> {
        self.store.color().or(self.def.color)
    }

    /// The icon/color stored in the shared file itself (no `SourceDef` fallback).
    pub fn stored_icon(&self) -> &str {
        self.store.icon()
    }

    pub fn stored_color(&self) -> Option<[u8; 3]> {
        self.store.color()
    }

    /// Sets the source's icon and color in the shared file (write-through), so the
    /// appearance travels with the sessions and every user sees it.
    pub fn set_appearance(&mut self, icon: &str, color: Option<[u8; 3]>) -> Result<()> {
        self.mutate("Update source appearance", |s| s.set_appearance(icon, color))
    }

    /// Sets the icon/color in the in-memory store only, to be persisted by the next
    /// `create()` — used when first creating a brand-new source's file.
    pub fn prime_appearance(&mut self, icon: &str, color: Option<[u8; 3]>) {
        let _ = self.store.set_appearance(icon, color);
    }

    /// Whether there are local changes not yet pushed to the remote (git only).
    pub fn has_pending(&self) -> bool {
        self.backend.has_pending()
    }

    /// Human-readable summaries of the changes a push would send — the pending
    /// commit subjects (e.g. "Session deleted: …"), most recent first. Empty for
    /// a folder share (no history) or when nothing is pending. For previewing a
    /// push before confirming it.
    pub fn pending_commits(&self) -> Vec<String> {
        self.backend.pending_commits()
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
    /// refused while the share is offline, to avoid conflicting with it. `message`
    /// describes the change and becomes the git commit subject.
    fn mutate(
        &mut self,
        message: &str,
        f: impl FnOnce(&mut SessionStore) -> Result<()>,
    ) -> Result<()> {
        if !self.available {
            anyhow::bail!("the shared source is offline; changes are disabled");
        }
        f(&mut self.store)?;
        self.write_through(message)
    }

    /// (Re)creates the shared file from the current cache contents, publishing it
    /// immediately (this is a deliberate setup action, so it pushes right away).
    pub fn create(&mut self) -> Result<()> {
        self.store.ensure_ids();
        tree::sync_tree(&self.store, self.backend.work_dir())
            .context("could not prepare the shared tree")?;
        self.backend.publish("Create shared source")?;
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
        self.missing && matches!(*self.backend, Backend::Folder { .. })
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
        // "created" for a new id, "updated" when replacing an existing session.
        let verb = if self.store.get(&session.id).is_some() { "updated" } else { "created" };
        let message = format!("Session {verb}: {}", session_location(&session.folder, &session.name));
        self.mutate(&message, |s| s.upsert(session))
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        // Resolve the name/location before the session is gone.
        let message = match self.store.get(id) {
            Some(s) => format!("Session deleted: {}", session_location(&s.folder, &s.name)),
            None => "Session deleted".to_owned(),
        };
        self.mutate(&message, |s| s.remove(id).map(|_| ()))
    }

    pub fn add_folder(&mut self, name: &str) -> Result<()> {
        let message = format!("Folder created: {}", folder_breadcrumb(name));
        self.mutate(&message, |s| s.add_folder(name).map(|_| ()))
    }

    pub fn remove_folder(&mut self, name: &str) -> Result<()> {
        let message = format!("Folder deleted: {}", folder_breadcrumb(name));
        self.mutate(&message, |s| s.remove_folder(name))
    }

    pub fn rename_folder(&mut self, old: &str, new: &str) -> Result<()> {
        let message =
            format!("Folder renamed: {} → {}", folder_breadcrumb(old), folder_breadcrumb(new));
        self.mutate(&message, |s| s.rename_folder(old, new))
    }

    pub fn move_to_folder(&mut self, id: &str, folder: &str) -> Result<()> {
        let name = self.store.get(id).map(|s| s.name.clone()).unwrap_or_else(|| "session".to_owned());
        let dest = if folder.is_empty() { "root".to_owned() } else { folder_breadcrumb(folder) };
        let message = format!("Session moved: {name} → {dest}");
        self.mutate(&message, |s| s.move_to_folder(id, folder))
    }

    pub fn set_folder_style(
        &mut self,
        folder: &str,
        style: wazowski_core::FolderStyle,
    ) -> Result<()> {
        let message = format!("Folder restyled: {}", folder_breadcrumb(folder));
        self.mutate(&message, |s| s.set_folder_style(folder, style))
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
        // A folder share is now a *directory* holding the exploded tree.
        let share = dir.path().join("share");
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

        // A brand-new source has no tree yet; create() lays one down.
        let mut source = SharedSource::open(def.clone(), &cache, None);
        assert!(!source.available());
        source.create().unwrap();
        assert!(source.available());
        source.upsert(Session::new("web", "example.com", "root")).unwrap();
        source.set_description("Team servers").unwrap();
        source.set_appearance("🌐", Some([1, 2, 3])).unwrap();
        assert!(share.join(".folder").exists(), "share tree should be written");
        assert_eq!(source.store().all().len(), 1);

        // Reopen from the share: description and appearance live in the root
        // `.folder`, so they travel with the sessions (every user sees them).
        let reopened = SharedSource::open(def.clone(), &cache, None);
        assert_eq!(reopened.description(), "Team servers", "description travels in the tree");
        assert_eq!(reopened.stored_icon(), "🌐", "icon travels in the tree");
        assert_eq!(reopened.stored_color(), Some([1, 2, 3]), "color travels in the tree");
        assert_eq!(reopened.store().all().len(), 1);
        // The username was not persisted to the shared tree (prompt or vault only);
        // it only ever lives in memory for the current connection.
        assert_eq!(reopened.store().all()[0].username, "", "username is never persisted");

        // Reopen from cache with the share removed: session still present, offline.
        fs::remove_dir_all(&share).unwrap();
        let offline = SharedSource::open(def, &cache, None);
        assert!(!offline.available());
        assert_eq!(offline.store().all().len(), 1, "cache keeps sessions when offline");
        assert_eq!(offline.description(), "Team servers", "description available offline too");
    }

    #[test]
    fn breadcrumbs_for_commit_messages() {
        assert_eq!(folder_breadcrumb(""), "");
        assert_eq!(folder_breadcrumb("work"), "work");
        assert_eq!(folder_breadcrumb("work/prod"), "work 📂 prod");
        assert_eq!(folder_breadcrumb("work/prod/db"), "work 📂 prod 📂 db");
        // A trailing/leading slash doesn't produce empty crumbs.
        assert_eq!(folder_breadcrumb("work/"), "work");

        // Session name, a `|` divider, then the folder path that contains it.
        assert_eq!(session_location("", "db"), "db");
        assert_eq!(session_location("work/prod", "db"), "db | work 📂 prod");
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
        // The push preview lists only the genuinely-unpushed commit subjects
        // (descriptive). create() already pushed "Create sessions file", so just
        // the new session's commit is pending.
        let preview = a.pending_commits();
        assert_eq!(preview, vec!["Session created: web".to_owned()], "preview: {preview:?}");
        a.push().unwrap();
        assert!(!a.has_pending(), "pushing clears the pending state");
        assert!(a.pending_commits().is_empty(), "nothing to preview after a push");

        // A second clone of the same remote sees the pushed session.
        let cache_b = dir.path().join("cache-b");
        let b = SharedSource::open(git_def("g2", &url), &cache_b, None);
        assert!(b.available(), "second clone should be online: {:?}", b.status());
        assert_eq!(b.store().all().len(), 1, "pushed session should sync via git");
    }

    // The payoff of the tree format: independent edits from two clones of one repo
    // (different session files) merge cleanly. A push that's behind the shared
    // branch rebases and integrates instead of being rejected as non-fast-forward.
    #[test]
    #[ignore = "requires the git binary"]
    fn independent_edits_from_two_clones_merge() {
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

        // User A seeds the shared tree with a session and pushes.
        let mut a = SharedSource::open(git_def("a", &url), &dir.path().join("a"), None);
        a.create().unwrap();
        a.upsert(Session::new("hostA", "a.example.com", "root")).unwrap();
        a.push().unwrap();

        // User B clones the same repo (sees A's session) and edits a different one.
        let mut b = SharedSource::open(git_def("b", &url), &dir.path().join("b"), None);
        assert_eq!(b.store().all().len(), 1, "B sees A's session");
        b.upsert(Session::new("hostB", "b.example.com", "root")).unwrap();

        // Meanwhile A pushes another change, so B is behind. B's push must rebase
        // and integrate (different files → clean merge), not be rejected.
        a.upsert(Session::new("hostA2", "a2.example.com", "root")).unwrap();
        a.push().unwrap();
        b.push().unwrap();
        assert!(!b.has_pending(), "B's push should clear its pending state");

        // A fresh clone sees all three independently-edited sessions.
        let c = SharedSource::open(git_def("c", &url), &dir.path().join("c"), None);
        assert_eq!(c.store().all().len(), 3, "independent edits all merged");
    }

    // An old single-file repo is upgraded to the tree on first open: the session
    // survives, its inline username is dropped, and the migration is a pending
    // commit that, once pushed, gives a fresh clone the tree.
    #[test]
    #[ignore = "requires the git binary"]
    fn migrates_legacy_single_file_to_tree() {
        use std::process::Command;
        let git = |cwd: &Path, args: &[&str]| {
            assert!(
                Command::new("git").arg("-C").arg(cwd).args(args).status().unwrap().success(),
                "git {args:?}"
            );
        };
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

        // Seed the remote with the OLD single-file layout (git_def uses sessions.toml).
        let seed = dir.path().join("seed");
        assert!(Command::new("git").arg("clone").arg(&url).arg(&seed).status().unwrap().success());
        let old = "[[session]]\nid = \"aaaaaaaaaaaaaaaa\"\nname = \"legacy box\"\n\
                   host = \"h.example.com\"\nusername = \"bob\"\n";
        fs::write(seed.join("sessions.toml"), old).unwrap();
        git(&seed, &["add", "-A"]);
        git(&seed, &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "seed"]);
        git(&seed, &["push", "-u", "origin", "HEAD"]);

        // Open fresh: the single file is migrated into the tree.
        let mut s = SharedSource::open(git_def("m1", &url), &dir.path().join("cache"), None);
        assert!(s.available(), "migrated source should be available: {:?}", s.status());
        assert_eq!(s.store().all().len(), 1);
        assert_eq!(s.store().all()[0].name, "legacy box");
        assert_eq!(s.store().all()[0].username, "", "username dropped during migration");
        assert!(s.has_pending(), "migration is a local commit pending a push");
        s.push().unwrap();

        // A fresh clone gets the tree, and the old single file is gone.
        let c = SharedSource::open(git_def("m2", &url), &dir.path().join("cache2"), None);
        assert_eq!(c.store().all().len(), 1);
        assert_eq!(c.store().all()[0].name, "legacy box");
        assert!(
            !c.backend.work_dir().join("sessions.toml").exists(),
            "old single file removed by the migration"
        );
    }
}
