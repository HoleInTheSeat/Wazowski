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
        let configs = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<ServersFile>(&text)
                .with_context(|| format!("could not parse {}", path.display()))?
                .servers,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        Ok(Self { path, configs })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
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

