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
    /// Save a terminal tab's output, or screenshot an RDP/VNC tab.
    SaveTab,
    Find,
    BaudUp,
    BaudDown,
    // The pane shortcuts were reorganized in 2.7 (Files/Macros swapped, Tools and
    // Vault added). They persist under new `pane_*` keys so a `keybindings.toml`
    // from an older version — which maps `view_*` to the old layout — is ignored
    // for these, letting the new defaults take effect. Other binds are untouched.
    #[serde(rename = "pane_sessions")]
    ViewSessions,
    #[serde(rename = "pane_files")]
    ViewFiles,
    #[serde(rename = "pane_macros")]
    ViewMacros,
    #[serde(rename = "pane_tools")]
    ViewTools,
    #[serde(rename = "pane_vault")]
    ViewVault,
    #[serde(rename = "pane_settings")]
    ViewSettings,
    FontSizeUp,
    FontSizeDown,
    FontSizeReset,
}

impl Action {
    pub const ALL: [Action; 21] = [
        Action::NewShell,
        Action::CloseTab,
        Action::NextTab,
        Action::PrevTab,
        Action::SplitRight,
        Action::SplitDown,
        Action::ClosePane,
        Action::ToggleBroadcast,
        Action::SaveTab,
        Action::Find,
        Action::BaudUp,
        Action::BaudDown,
        Action::ViewSessions,
        Action::ViewFiles,
        Action::ViewMacros,
        Action::ViewTools,
        Action::ViewVault,
        Action::ViewSettings,
        Action::FontSizeUp,
        Action::FontSizeDown,
        Action::FontSizeReset,
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
            Action::SaveTab => "Save output / screenshot",
            Action::Find => "Find in terminals",
            Action::BaudUp => "Serial: raise baud",
            Action::BaudDown => "Serial: lower baud",
            Action::ViewSessions => "Sessions pane",
            Action::ViewFiles => "Files pane",
            Action::ViewMacros => "Macros pane",
            Action::ViewTools => "Tools pane",
            Action::ViewVault => "Vault pane",
            Action::ViewSettings => "Settings pane",
            Action::FontSizeUp => "Terminal: larger font",
            Action::FontSizeDown => "Terminal: smaller font",
            Action::FontSizeReset => "Terminal: reset font size",
        }
    }

    /// The stable snake_case key used to persist this action in
    /// `keybindings.toml` (kept in sync with the serde `rename_all`). Reading
    /// via this (rather than serde) lets a saved file carry keys for actions
    /// that no longer exist without failing the whole load.
    fn from_key(key: &str) -> Option<Action> {
        Some(match key {
            "new_shell" => Action::NewShell,
            "close_tab" => Action::CloseTab,
            "next_tab" => Action::NextTab,
            "prev_tab" => Action::PrevTab,
            "split_right" => Action::SplitRight,
            "split_down" => Action::SplitDown,
            "close_pane" => Action::ClosePane,
            "toggle_broadcast" => Action::ToggleBroadcast,
            "save_tab" => Action::SaveTab,
            "find" => Action::Find,
            "baud_up" => Action::BaudUp,
            "baud_down" => Action::BaudDown,
            "pane_sessions" => Action::ViewSessions,
            "pane_files" => Action::ViewFiles,
            "pane_macros" => Action::ViewMacros,
            "pane_tools" => Action::ViewTools,
            "pane_vault" => Action::ViewVault,
            "pane_settings" => Action::ViewSettings,
            "font_size_up" => Action::FontSizeUp,
            "font_size_down" => Action::FontSizeDown,
            "font_size_reset" => Action::FontSizeReset,
            _ => return None,
        })
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
            // Plain Ctrl+S (normally the terminal's XOFF) is overridden to save the
            // tab's output / screenshot; rebindable if you need XOFF.
            Action::SaveTab => KeyboardShortcut::new(ctrl, Key::S),
            Action::Find => KeyboardShortcut::new(ctrl_shift, Key::F),
            Action::BaudUp => KeyboardShortcut::new(ctrl_shift, Key::ArrowUp),
            Action::BaudDown => KeyboardShortcut::new(ctrl_shift, Key::ArrowDown),
            Action::ViewSessions => KeyboardShortcut::new(ctrl_shift, Key::Num1),
            Action::ViewFiles => KeyboardShortcut::new(ctrl_shift, Key::Num2),
            Action::ViewMacros => KeyboardShortcut::new(ctrl_shift, Key::Num3),
            Action::ViewTools => KeyboardShortcut::new(ctrl_shift, Key::Num4),
            Action::ViewVault => KeyboardShortcut::new(ctrl_shift, Key::Num5),
            Action::ViewSettings => KeyboardShortcut::new(ctrl_shift, Key::S),
            Action::FontSizeUp => KeyboardShortcut::new(ctrl, Key::Equals),
            Action::FontSizeDown => KeyboardShortcut::new(ctrl, Key::Minus),
            Action::FontSizeReset => KeyboardShortcut::new(ctrl, Key::Num0),
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
                // Parse with string keys so an entry for an action that no longer
                // exists is skipped rather than failing the whole load (which would
                // silently wipe every custom binding).
                let saved: BTreeMap<String, String> = toml::from_str(&text)
                    .with_context(|| format!("could not parse {}", path.display()))?;
                for (key, value) in saved {
                    if let (Some(action), Some(shortcut)) =
                        (Action::from_key(&key), parse_shortcut(&value))
                    {
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
    fn load_skips_removed_actions_and_keeps_custom_binds() {
        // A keybindings.toml from an older version carries keys for actions that
        // no longer exist (e.g. `run_macro`). Loading must skip those rather than
        // fail the whole parse, so the user's other custom binds survive.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keybindings.toml");
        // Old file: a removed action, a custom bind, and the pre-2.7 pane layout.
        fs::write(
            &path,
            "run_macro = \"Ctrl+Shift+M\"\n\
             new_shell = \"Ctrl+Shift+J\"\n\
             view_macros = \"Ctrl+Shift+2\"\n\
             view_files = \"Ctrl+Shift+3\"\n",
        )
        .unwrap();
        let map = Keymap::load(path).unwrap();
        // A genuine custom bind under an unchanged key survives.
        assert_eq!(map.text(Action::NewShell), "Ctrl+Shift+J");
        // An untouched action still has its default.
        assert_eq!(map.get(Action::CloseTab), Action::CloseTab.default_shortcut());
        // The old `view_*` pane keys are ignored, so the new defaults apply
        // (Files=2, Macros=3) rather than the old swapped layout.
        assert_eq!(map.get(Action::ViewFiles), Action::ViewFiles.default_shortcut());
        assert_eq!(map.get(Action::ViewMacros), Action::ViewMacros.default_shortcut());
        assert_eq!(map.text(Action::ViewFiles), "Ctrl+Shift+2");
        assert_eq!(map.text(Action::ViewMacros), "Ctrl+Shift+3");
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
