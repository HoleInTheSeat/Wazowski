//! Configurable keyboard shortcuts.
//!
//! Each [`Action`] has a default [`KeyboardShortcut`]; a [`Keymap`] holds the
//! current binding for every action, loads overrides from `keybindings.toml`,
//! and saves changes made in the Settings dialog.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use eframe::egui::{Key, KeyboardShortcut, Modifiers};
use serde::{Deserialize, Serialize};

/// Something the user can bind a shortcut to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    NewShell,
    CloseTab,
    NextTab,
    PrevTab,
    SplitRight,
    SplitDown,
    ClosePane,
    ToggleBroadcast,
    RunMacro,
    Find,
}

impl Action {
    pub const ALL: [Action; 10] = [
        Action::NewShell,
        Action::CloseTab,
        Action::NextTab,
        Action::PrevTab,
        Action::SplitRight,
        Action::SplitDown,
        Action::ClosePane,
        Action::ToggleBroadcast,
        Action::RunMacro,
        Action::Find,
    ];

    /// Human-readable name shown in the Settings dialog and menus.
    pub fn label(self) -> &'static str {
        match self {
            Action::NewShell => "New local shell",
            Action::CloseTab => "Close tab",
            Action::NextTab => "Next tab",
            Action::PrevTab => "Previous tab",
            Action::SplitRight => "Split pane right",
            Action::SplitDown => "Split pane down",
            Action::ClosePane => "Close focused pane",
            Action::ToggleBroadcast => "Toggle broadcast",
            Action::RunMacro => "Run macro…",
            Action::Find => "Find in terminals",
        }
    }

    fn default_shortcut(self) -> KeyboardShortcut {
        let ctrl = Modifiers::CTRL;
        let ctrl_shift = Modifiers::CTRL.plus(Modifiers::SHIFT);
        match self {
            Action::NewShell => KeyboardShortcut::new(ctrl_shift, Key::T),
            Action::CloseTab => KeyboardShortcut::new(ctrl_shift, Key::W),
            Action::NextTab => KeyboardShortcut::new(ctrl, Key::PageDown),
            Action::PrevTab => KeyboardShortcut::new(ctrl, Key::PageUp),
            // Plain Ctrl+<key> is reserved for terminal control codes (Ctrl+M is
            // Enter, Ctrl+\ is SIGQUIT), so app actions use Ctrl+Shift.
            Action::SplitRight => KeyboardShortcut::new(ctrl_shift, Key::E),
            Action::SplitDown => KeyboardShortcut::new(ctrl_shift, Key::O),
            Action::ClosePane => KeyboardShortcut::new(ctrl_shift, Key::X),
            Action::ToggleBroadcast => KeyboardShortcut::new(ctrl_shift, Key::B),
            Action::RunMacro => KeyboardShortcut::new(ctrl_shift, Key::M),
            Action::Find => KeyboardShortcut::new(ctrl_shift, Key::F),
        }
    }
}

/// The active binding for every action, with persistence.
pub struct Keymap {
    path: Option<PathBuf>,
    binds: BTreeMap<Action, KeyboardShortcut>,
}

impl Keymap {
    /// Defaults with no backing file (used as a fallback if the path is unknown).
    pub fn defaults() -> Self {
        let binds = Action::ALL.iter().map(|&a| (a, a.default_shortcut())).collect();
        Self { path: None, binds }
    }

    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("keybindings.toml"))
    }

    /// Loads overrides from `path`, falling back to defaults for anything unset
    /// or unparseable. A missing file is fine.
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut map = Self::defaults();
        map.path = Some(path.clone());
        match fs::read_to_string(&path) {
            Ok(text) => {
                let saved: BTreeMap<Action, String> = toml::from_str(&text)
                    .with_context(|| format!("could not parse {}", path.display()))?;
                for (action, value) in saved {
                    if let Some(shortcut) = parse_shortcut(&value) {
                        map.binds.insert(action, shortcut);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        }
        Ok(map)
    }

    pub fn get(&self, action: Action) -> KeyboardShortcut {
        self.binds.get(&action).copied().unwrap_or_else(|| action.default_shortcut())
    }

    pub fn set(&mut self, action: Action, shortcut: KeyboardShortcut) {
        self.binds.insert(action, shortcut);
    }

    pub fn reset(&mut self, action: Action) {
        self.binds.insert(action, action.default_shortcut());
    }

    /// The shortcut as a storable/displayable string, e.g. `Ctrl+Shift+T`.
    pub fn text(&self, action: Action) -> String {
        format_shortcut(&self.get(action))
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let saved: BTreeMap<Action, String> =
            self.binds.iter().map(|(&a, s)| (a, format_shortcut(s))).collect();
        let text = toml::to_string_pretty(&saved).context("could not serialize keybindings")?;
        fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
    }
}

/// Formats a shortcut as `Ctrl+Shift+Key`, in a form [`parse_shortcut`] reads back.
pub fn format_shortcut(s: &KeyboardShortcut) -> String {
    let mut parts = Vec::new();
    let m = s.modifiers;
    if m.ctrl {
        parts.push("Ctrl".to_owned());
    }
    if m.command {
        parts.push("Cmd".to_owned());
    }
    if m.alt {
        parts.push("Alt".to_owned());
    }
    if m.shift {
        parts.push("Shift".to_owned());
    }
    parts.push(s.logical_key.name().to_owned());
    parts.join("+")
}

/// Parses `Ctrl+Shift+Key`. Returns `None` if there is no non-modifier key.
pub fn parse_shortcut(s: &str) -> Option<KeyboardShortcut> {
    let mut modifiers = Modifiers::NONE;
    let mut key = None;
    for token in s.split('+') {
        let token = token.trim();
        match token.to_ascii_lowercase().as_str() {
            "" => {}
            "ctrl" | "control" => modifiers.ctrl = true,
            "alt" | "option" => modifiers.alt = true,
            "shift" => modifiers.shift = true,
            "cmd" | "command" | "super" | "win" | "meta" => modifiers.command = true,
            _ => key = Key::from_name(token),
        }
    }
    Some(KeyboardShortcut::new(modifiers, key?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_default() {
        for action in Action::ALL {
            let shortcut = action.default_shortcut();
            let text = format_shortcut(&shortcut);
            assert_eq!(parse_shortcut(&text), Some(shortcut), "failed for {text}");
        }
    }

    #[test]
    fn parses_aliases_and_rejects_modifier_only() {
        assert_eq!(
            parse_shortcut("ctrl+\\"),
            Some(KeyboardShortcut::new(Modifiers::CTRL, Key::Backslash))
        );
        assert!(parse_shortcut("Ctrl+Shift").is_none());
    }
}
