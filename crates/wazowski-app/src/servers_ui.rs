//! Quick-servers state: persisted configs, running handles, and the add/edit form.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use wazowski_servers::{RunningServer, ServerConfig, ServerKind};

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

    pub fn remove(&mut self, id: &str) -> Result<()> {
        self.configs.retain(|c| c.id != id);
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
}

impl ServerEntry {
    pub fn new(config: ServerConfig) -> Self {
        Self { config, running: None, log: Vec::new(), stop_at: None }
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
}

/// Fields for the add/edit-server dialog.
pub struct ServerForm {
    pub id: Option<String>,
    pub name: String,
    pub kind: ServerKind,
    pub root: String,
    pub bind: IpAddr,
    pub port: String,
    pub writable: bool,
    pub username: String,
    pub password: String,
    pub error: Option<String>,
}

impl ServerForm {
    pub fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            kind: ServerKind::Http,
            root: String::new(),
            bind: IpAddr::from([0, 0, 0, 0]),
            port: ServerKind::Http.default_port().to_string(),
            writable: false,
            username: String::new(),
            password: String::new(),
            error: None,
        }
    }

    pub fn from_config(c: &ServerConfig) -> Self {
        Self {
            id: Some(c.id.clone()),
            name: c.name.clone(),
            kind: c.kind,
            root: c.root.to_string_lossy().into_owned(),
            bind: c.bind,
            port: c.port.to_string(),
            writable: c.writable,
            username: c.username.clone(),
            password: c.password.clone(),
            error: None,
        }
    }
}
