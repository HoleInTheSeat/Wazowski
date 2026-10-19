//! Export/import of a user's Wazowski configuration as a single portable file.
//!
//! All of Wazowski's settings live as separate TOML files in the config dir
//! (`~/.config/wazowski/` on Linux): the general settings, shared-source setup,
//! local sessions, macros, quick servers, keybindings and highlight rules. A
//! backup bundles those into one file so a user can copy it elsewhere and import
//! it into another instance.
//!
//! The encrypted vault (passwords/keys) and OS-keyring items (git tokens) are
//! deliberately left out — secrets have their own backup, and should not travel
//! in a plain settings file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// The config files included in a backup, relative to the config dir. These are
/// also the only names accepted on import (so a crafted bundle can't write
/// elsewhere).
const CONFIG_FILES: &[&str] = &[
    "settings.toml",
    "sources.toml",
    "sessions.toml",
    "macros.toml",
    "servers.toml",
    "keybindings.toml",
    "highlights.toml",
];

/// The default filename suggested when exporting.
pub const DEFAULT_FILENAME: &str = "wazowski-settings.toml";

/// A settings backup: metadata plus each config file's bytes, base64-encoded so
/// arbitrary TOML content survives round-tripping cleanly.
#[derive(Serialize, Deserialize)]
struct Bundle {
    /// A marker so import can recognise the file.
    kind: String,
    /// The app version that wrote the backup (informational).
    app_version: String,
    /// Seconds since the Unix epoch when it was written (informational).
    exported_unix: u64,
    /// `filename` -> base64 of the file's bytes.
    files: BTreeMap<String, String>,
}

const BUNDLE_KIND: &str = "wazowski-settings-backup";

/// The Wazowski config directory.
fn config_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
        .context("could not determine a config directory")?;
    Ok(dirs.config_dir().to_path_buf())
}

/// Builds a backup of the current config files and writes it to `dest`.
pub fn export_to(dest: &Path) -> Result<()> {
    let dir = config_dir()?;
    let mut files = BTreeMap::new();
    for name in CONFIG_FILES {
        let path = dir.join(name);
        match std::fs::read(&path) {
            Ok(bytes) => {
                files.insert(
                    (*name).to_owned(),
                    base64::engine::general_purpose::STANDARD.encode(bytes),
                );
            }
            // A config file that was never created is simply omitted.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
    let bundle = Bundle {
        kind: BUNDLE_KIND.to_owned(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        exported_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        files,
    };
    let text = toml::to_string_pretty(&bundle).context("serializing the backup")?;
    std::fs::write(dest, text).with_context(|| format!("writing {}", dest.display()))
}

/// Restores a backup: writes each bundled config file into the config dir,
/// overwriting what's there. Returns the names of the files restored.
pub fn import_from(src: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(src).with_context(|| format!("reading {}", src.display()))?;
    let bundle: Bundle = toml::from_str(&text)
        .context("this file is not a Wazowski settings backup")?;
    if bundle.kind != BUNDLE_KIND {
        anyhow::bail!("this file is not a Wazowski settings backup");
    }
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir).ok();
    let mut restored = Vec::new();
    for (name, encoded) in &bundle.files {
        // Only known config filenames — never an absolute or traversing path.
        if !CONFIG_FILES.contains(&name.as_str()) {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("decoding {name}"))?;
        let path = dir.join(name);
        std::fs::write(&path, &bytes).with_context(|| format!("writing {}", path.display()))?;
        restored.push(name.clone());
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_backup_files() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-backup.toml");
        std::fs::write(&bogus, "hello = 1\n").unwrap();
        assert!(import_from(&bogus).is_err());
    }

    #[test]
    fn ignores_unknown_filenames_in_a_bundle() {
        // A bundle naming a file outside the allow-list contributes nothing.
        let bundle = Bundle {
            kind: BUNDLE_KIND.to_owned(),
            app_version: "test".into(),
            exported_unix: 0,
            files: BTreeMap::from([(
                "../evil.toml".to_owned(),
                base64::engine::general_purpose::STANDARD.encode(b"x"),
            )]),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.toml");
        std::fs::write(&path, toml::to_string_pretty(&bundle).unwrap()).unwrap();
        let restored = import_from(&path).unwrap();
        assert!(restored.is_empty(), "unknown filenames are skipped");
    }
}
