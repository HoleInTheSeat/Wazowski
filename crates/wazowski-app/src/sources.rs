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

/// A configured shared source (persisted in `sources.toml`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceDef {
    pub id: String,
    pub name: String,
    /// Path to the shared sessions file.
    pub path: PathBuf,
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
    store: SessionStore,
    /// Whether the shared file was reachable at the last load/sync.
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
        let mut source = Self {
            def,
            cache_path,
            store: SessionStore::default(),
            available: false,
            missing: false,
            status: None,
        };
        source.reload();
        source
    }

    /// Re-reads the shared file (refreshing the cache) and reloads the store.
    pub fn reload(&mut self) {
        if let Some(parent) = self.cache_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::read(&self.def.path) {
            Ok(bytes) => {
                // Refresh the cache from the share, then load from the cache.
                if let Err(e) = fs::write(&self.cache_path, &bytes) {
                    self.status = Some(format!("could not update cache: {e}"));
                }
                self.available = true;
                self.missing = false;
                self.status = None;
            }
            Err(e) => {
                // The shared file is unreachable (deleted, or the location is
                // offline). Fall back to the cache, read-only, and tell the user.
                self.available = false;
                self.missing = e.kind() == std::io::ErrorKind::NotFound;
                self.status = Some(if self.missing {
                    "shared file not found — using local cache (read-only)".into()
                } else {
                    format!("share offline ({e}) — using local cache (read-only)")
                });
            }
        }
        // Load from the cache (empty store if neither share nor cache exists).
        self.store = SessionStore::load(self.cache_path.clone()).unwrap_or_default();
    }

    /// Writes the current store to the shared file (and refreshes the cache).
    fn write_through(&mut self) -> Result<()> {
        self.store
            .save_as(&self.def.path)
            .with_context(|| format!("could not write {}", self.def.path.display()))?;
        let _ = self.store.save_as(&self.cache_path);
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
        let def = SourceDef { id: "t1".into(), name: "Team".into(), path: share.clone() };

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
        cfg.add(SourceDef { id: "a".into(), name: "A".into(), path: "/x/a.toml".into() }).unwrap();
        let reloaded = SourcesConfig::load(path).unwrap();
        assert_eq!(reloaded.defs.len(), 1);
        assert_eq!(reloaded.defs[0].name, "A");
    }
}
