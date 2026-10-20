//! Quick-servers state: persisted configs, running handles, and the add/edit form.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use wazowski_servers::{RunningServer, ServerConfig};

/// Persisted list of server configs (`servers.toml`).
#[derive(Default, Serialize, Deserialize)]
struct ServersFile {
    #[serde(default, rename = "server")]
    servers: Vec<ServerConfig>,
}

/// The keyring service holding SFTP server passwords (keyed by server id), so a
/// listener password never lands in `servers.toml` (or a settings backup).
const SFTP_PW_SERVICE: &str = "org.wazowski.sftp-password";

/// Stores (or clears, when empty) a server's SFTP password in the OS keyring.
fn store_sftp_password(id: &str, password: &str) {
    if let Ok(entry) = keyring::Entry::new(SFTP_PW_SERVICE, id) {
        if password.is_empty() {
            let _ = entry.delete_credential();
        } else {
            let _ = entry.set_password(password);
        }
    }
}

/// Loads a server's SFTP password from the OS keyring (empty if none).
fn load_sftp_password(id: &str) -> String {
    keyring::Entry::new(SFTP_PW_SERVICE, id)
        .ok()
        .and_then(|e| e.get_password().ok())
        .unwrap_or_default()
}

pub struct ServersStore {
    path: PathBuf,
    pub configs: Vec<ServerConfig>,
}

impl ServersStore {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("servers.toml"))
    }

    pub fn load(path: PathBuf) -> Result<Self> {
        let mut configs = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<ServersFile>(&text)
                .with_context(|| format!("could not parse {}", path.display()))?
                .servers,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        // Passwords live in the keyring, not the file. Prefer the keyring value;
        // if a legacy plaintext password is still in the file, migrate it in and
        // rewrite the file without it.
        let mut migrated = false;
        for c in &mut configs {
            let stored = load_sftp_password(&c.id);
            if !stored.is_empty() {
                c.password = stored;
            } else if !c.password.is_empty() {
                store_sftp_password(&c.id, &c.password);
                migrated = true;
            }
        }
        let store = Self { path, configs };
        if migrated {
            let _ = store.save();
        }
        Ok(store)
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Mirror each password into the keyring; `skip_serializing` keeps it out
        // of the written file.
        for c in &self.configs {
            store_sftp_password(&c.id, &c.password);
        }
        let file = ServersFile { servers: self.configs.clone() };
        let text = toml::to_string_pretty(&file).context("could not serialize servers")?;
        fs::write(&self.path, text).with_context(|| format!("could not write {}", self.path.display()))
    }

    pub fn upsert(&mut self, config: ServerConfig) -> Result<()> {
        match self.configs.iter_mut().find(|c| c.id == config.id) {
            Some(existing) => *existing = config,
            None => self.configs.push(config),
        }
        self.save()
    }

}

/// A server config plus its running handle and log buffer.
pub struct ServerEntry {
    pub config: ServerConfig,
    pub running: Option<RunningServer>,
    pub log: Vec<String>,
    /// When to auto-stop the server, if a timer was set.
    pub stop_at: Option<std::time::Instant>,
    /// Inline "stop after N minutes" toggle and value (UI state, not persisted).
    pub auto_stop: bool,
    pub stop_minutes: String,
}

impl ServerEntry {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            running: None,
            log: Vec::new(),
            stop_at: None,
            auto_stop: false,
            stop_minutes: "60".to_owned(),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
}

