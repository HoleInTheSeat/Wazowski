//! User-configurable terminal highlight rules: regex patterns that color
//! matching text in the terminal. Ships with defaults; all rules (including the
//! defaults) can be edited, recolored, toggled, or removed, and persist to
//! `highlights.toml`.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use egui::Color32;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// One highlight rule.
#[derive(Clone, Serialize, Deserialize)]
pub struct HighlightRule {
    pub pattern: String,
    /// sRGB color applied to matching text.
    pub color: [u8; 3],
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

/// The built-in default rules (also used by "Restore defaults").
pub fn default_rules() -> Vec<HighlightRule> {
    let rule = |pattern: &str, color: [u8; 3]| HighlightRule {
        pattern: pattern.to_owned(),
        color,
        enabled: true,
    };
    vec![
        rule(r"(?i)\b(error|errors|failed|failure|fatal|denied|critical)\b", [230, 80, 80]),
        rule(r"(?i)\b(warn|warning|warnings|deprecated)\b", [235, 180, 60]),
        rule(r"(?i)\b(success|succeeded|ok|done|passed|enabled|active|up)\b", [120, 200, 120]),
        // IPv4 addresses.
        rule(r"\b\d{1,3}(\.\d{1,3}){3}\b", [110, 200, 220]),
    ]
}

#[derive(Default, Serialize, Deserialize)]
struct HighlightsFile {
    #[serde(default, rename = "rule")]
    rules: Vec<HighlightRule>,
}

/// The rule list plus its compiled form, persisted to disk.
pub struct HighlightStore {
    path: Option<PathBuf>,
    pub rules: Vec<HighlightRule>,
    /// Compiled (regex, color) for enabled, valid rules.
    compiled: Vec<(Regex, Color32)>,
}

impl HighlightStore {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("highlights.toml"))
    }

    /// Loads rules, seeding (and saving) the defaults the first time.
    pub fn load(path: PathBuf) -> Result<Self> {
        let rules = match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str::<HighlightsFile>(&text)
                    .with_context(|| format!("could not parse {}", path.display()))?
                    .rules
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => default_rules(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        let mut store = Self { path: Some(path), rules, compiled: Vec::new() };
        store.recompile();
        let _ = store.save(); // ensure the defaults file exists
        Ok(store)
    }

    pub fn load_or_default() -> Self {
        Self::default_path().and_then(Self::load).unwrap_or_else(|_| {
            let mut store = Self { path: None, rules: default_rules(), compiled: Vec::new() };
            store.recompile();
            store
        })
    }

    /// Recompiles the enabled, valid rules. Call after any edit.
    pub fn recompile(&mut self) {
        self.compiled = self
            .rules
            .iter()
            .filter(|r| r.enabled && !r.pattern.is_empty())
            .filter_map(|r| {
                Regex::new(&r.pattern).ok().map(|re| {
                    (re, Color32::from_rgb(r.color[0], r.color[1], r.color[2]))
                })
            })
            .collect();
    }

    /// The compiled rules to hand to the terminal view.
    pub fn compiled(&self) -> &[(Regex, Color32)] {
        &self.compiled
    }

    /// Whether a pattern is a valid regex (for the editor to flag bad input).
    pub fn is_valid(pattern: &str) -> bool {
        Regex::new(pattern).is_ok()
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = HighlightsFile { rules: self.rules.clone() };
        let text = toml::to_string_pretty(&file).context("could not serialize highlights")?;
        fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
    }
}
