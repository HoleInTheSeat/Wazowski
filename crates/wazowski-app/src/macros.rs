//! User-defined macros: named sequences of steps sent to terminals.
//!
//! A [`Macro`] is an ordered list of [`Step`]s — literal text, a key chord, a
//! pause, or an "expect" that waits for the terminal to show some output before
//! continuing. [`MacroStore`] persists them to `macros.toml`. Running a macro is
//! driven frame by frame by the app via a run-state machine; this module
//! provides the data model plus the key-chord-to-bytes translation.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

fn default_timeout() -> u64 {
    10_000
}

/// One action in a macro.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Send literal text, optionally followed by Enter.
    Text {
        text: String,
        #[serde(default)]
        enter: bool,
    },
    /// Send a key chord, e.g. `Enter`, `Ctrl+C`, `Up`, `Tab`.
    Key { chord: String },
    /// Wait until the terminal's visible text contains `text`, or `timeout_ms`
    /// elapses, before the next step.
    Expect {
        text: String,
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    },
    /// Pause for `ms` milliseconds.
    Delay { ms: u64 },
}

impl Step {
    /// A one-line summary for the confirmation dialog and editor.
    pub fn summary(&self) -> String {
        match self {
            Step::Text { text, enter } => {
                let tail = if *enter { " ⏎" } else { "" };
                format!("Type \"{}\"{tail}", truncate(text))
            }
            Step::Key { chord } => format!("Press {chord}"),
            Step::Expect { text, timeout_ms } => {
                format!("Wait for \"{}\" (≤{}s)", truncate(text), timeout_ms / 1000)
            }
            Step::Delay { ms } => format!("Wait {ms} ms"),
        }
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 32;
    if s.chars().count() > MAX {
        format!("{}…", s.chars().take(MAX).collect::<String>())
    } else {
        s.to_owned()
    }
}

/// A named sequence of steps.
#[derive(Clone, Serialize, Deserialize)]
pub struct Macro {
    pub name: String,
    #[serde(default, rename = "step")]
    pub steps: Vec<Step>,
}

/// Persisted list of macros (`macros.toml`).
#[derive(Default, Serialize, Deserialize)]
struct MacrosFile {
    #[serde(default, rename = "macro")]
    macros: Vec<Macro>,
}

pub struct MacroStore {
    path: Option<PathBuf>,
    pub macros: Vec<Macro>,
}

impl MacroStore {
    pub fn default_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("org", "wazowski", "wazowski")
            .context("could not determine a config directory")?;
        Ok(dirs.config_dir().join("macros.toml"))
    }

    pub fn load(path: PathBuf) -> Result<Self> {
        let macros = match fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str::<MacrosFile>(&text)
                    .with_context(|| format!("could not parse {}", path.display()))?
                    .macros
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        Ok(Self { path: Some(path), macros })
    }

    pub fn empty() -> Self {
        Self { path: None, macros: Vec::new() }
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = MacrosFile { macros: self.macros.clone() };
        let text = toml::to_string_pretty(&file).context("could not serialize macros")?;
        fs::write(path, text).with_context(|| format!("could not write {}", path.display()))
    }
}

/// Translates a key chord like `Ctrl+C`, `Enter`, or `Up` into the bytes a
/// terminal expects. Returns `None` for an unrecognised chord.
pub fn chord_to_bytes(chord: &str) -> Option<Vec<u8>> {
    let mut ctrl = false;
    let mut alt = false;
    let mut key = None;
    for token in chord.split('+') {
        let token = token.trim();
        match token.to_ascii_lowercase().as_str() {
            "" => {}
            "ctrl" | "control" => ctrl = true,
            "alt" | "option" | "meta" => alt = true,
            "shift" => {} // folded into the key itself
            _ => key = Some(token.to_owned()),
        }
    }
    let key = key?;
    let lower = key.to_ascii_lowercase();
    let mut bytes: Vec<u8> = match lower.as_str() {
        "enter" | "return" => vec![b'\r'],
        "tab" => vec![b'\t'],
        "esc" | "escape" => vec![0x1b],
        "space" => vec![b' '],
        "backspace" => vec![0x7f],
        "delete" | "del" => b"\x1b[3~".to_vec(),
        "up" => b"\x1b[A".to_vec(),
        "down" => b"\x1b[B".to_vec(),
        "right" => b"\x1b[C".to_vec(),
        "left" => b"\x1b[D".to_vec(),
        "home" => b"\x1b[H".to_vec(),
        "end" => b"\x1b[F".to_vec(),
        "pageup" => b"\x1b[5~".to_vec(),
        "pagedown" => b"\x1b[6~".to_vec(),
        // A single printable character.
        _ if key.chars().count() == 1 => {
            let c = key.chars().next().unwrap();
            if ctrl {
                // Control code: C-a = 0x01 .. C-z = 0x1a, and a few symbols.
                let upper = c.to_ascii_uppercase();
                let code = match upper {
                    'A'..='Z' => (upper as u8) - b'A' + 1,
                    '@' => 0,
                    '[' => 0x1b,
                    '\\' => 0x1c,
                    ']' => 0x1d,
                    '^' => 0x1e,
                    '_' => 0x1f,
                    ' ' => 0,
                    _ => return None,
                };
                vec![code]
            } else {
                let mut b = [0u8; 4];
                c.encode_utf8(&mut b).as_bytes().to_vec()
            }
        }
        _ => return None,
    };
    if alt {
        // Alt sends an ESC prefix.
        let mut out = vec![0x1b];
        out.append(&mut bytes);
        return Some(out);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chords_translate() {
        assert_eq!(chord_to_bytes("Enter"), Some(vec![b'\r']));
        assert_eq!(chord_to_bytes("Ctrl+C"), Some(vec![0x03]));
        assert_eq!(chord_to_bytes("Up"), Some(b"\x1b[A".to_vec()));
        assert_eq!(chord_to_bytes("Alt+x"), Some(vec![0x1b, b'x']));
        assert_eq!(chord_to_bytes("a"), Some(vec![b'a']));
        assert_eq!(chord_to_bytes("Ctrl+Shift+C"), Some(vec![0x03]));
        assert_eq!(chord_to_bytes("nonsense-key"), None);
    }

    #[test]
    fn macros_round_trip() {
        let m = Macro {
            name: "demo".into(),
            steps: vec![
                Step::Text { text: "ls".into(), enter: true },
                Step::Expect { text: "$".into(), timeout_ms: 5000 },
                Step::Key { chord: "Ctrl+C".into() },
                Step::Delay { ms: 200 },
            ],
        };
        let file = MacrosFile { macros: vec![m] };
        let text = toml::to_string_pretty(&file).unwrap();
        let back: MacrosFile = toml::from_str(&text).unwrap();
        assert_eq!(back.macros.len(), 1);
        assert_eq!(back.macros[0].steps.len(), 4);
    }
}
