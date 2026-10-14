//! Global, persisted application settings (`settings.toml`).

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// What Wazowski opens in the first tab at startup.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "session", rename_all = "snake_case")]
pub enum StartupTab {
    /// Start with no tab (the welcome screen).
    None,
    /// Start with a local shell (the historical default).
    #[default]
    LocalShell,
    /// Start by connecting to the saved session with this id.
    Session(String),
}

/// Where a newly opened tab is placed in the tab strip.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewTabPlacement {
    /// Always append at the far right.
    #[default]
    Never,
    /// Only a duplicated tab opens next to the current one; others append.
    WhenDuplicating,
    /// Always open directly next to the current tab.
    Always,
}

/// Automatic vault-backup configuration.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VaultBackup {
    pub enabled: bool,
    /// How often to back up, in days.
    #[serde(default = "default_backup_days")]
    pub every_days: u32,
    /// Destination folder; falls back to the config dir's `backups` when unset.
    pub dir: Option<PathBuf>,
    /// When the last automatic backup ran.
    pub last_backup: Option<SystemTime>,
}

fn default_backup_days() -> u32 {
    7
}

/// All persisted global settings.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Allow a second Wazowski process to run alongside this one.
    pub allow_multiple_instances: bool,
    pub startup_tab: StartupTab,
    pub new_tab_placement: NewTabPlacement,
    pub vault_backup: VaultBackup,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Settings {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("settings.toml"))
    }

    /// Loads settings from `path`, or defaults (remembering the path) if missing.
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut settings = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<Settings>(&text)
                .with_context(|| format!("could not parse {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        settings.path = Some(path);
        Ok(settings)
    }

    /// Loads from the default path, falling back to in-memory defaults on error.
    pub fn load_or_default() -> Self {
        Self::default_path().and_then(Self::load).unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self).context("could not serialize settings")?;
        fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
    }

    /// The effective backup directory (configured, or `backups` beside the config).
    pub fn backup_dir(&self) -> PathBuf {
        self.vault_backup.dir.clone().unwrap_or_else(|| {
            self.path
                .as_ref()
                .and_then(|p| p.parent())
                .map(|p| p.join("backups"))
                .unwrap_or_else(|| PathBuf::from("backups"))
        })
    }

    /// Whether an automatic vault backup is due.
    pub fn auto_backup_due(&self) -> bool {
        if !self.vault_backup.enabled {
            return false;
        }
        match self.vault_backup.last_backup {
            None => true,
            Some(last) => {
                let interval = Duration::from_secs(u64::from(self.vault_backup.every_days) * 86_400);
                last.elapsed().map(|e| e >= interval).unwrap_or(true)
            }
        }
    }
}
