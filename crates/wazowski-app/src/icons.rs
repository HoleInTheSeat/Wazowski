//! Bundled [Phosphor](https://phosphoricons.com/) icon glyphs (MIT), so the UI's
//! icons look identical on every platform instead of varying with the OS emoji
//! font. The font ships in the binary and is registered as a fallback family, so
//! any of these glyph strings renders wherever text does (see `install_fonts`).
//!
//! Glyphs live in the Unicode private-use area; each constant is a one-char
//! string ready to drop into a button or label.

// A palette of named glyphs; not every one is referenced yet, and that's fine.
#![allow(dead_code)]

/// The bundled Phosphor (regular) font.
pub const FONT: &[u8] = include_bytes!("../assets/Phosphor.ttf");

// ---- built-in UI icons -------------------------------------------------------
pub const DESKTOP: &str = "\u{e560}"; // Sessions / SSH host
pub const SCROLL: &str = "\u{eb7a}"; // Macros
pub const FOLDER: &str = "\u{e24a}";
pub const FOLDER_OPEN: &str = "\u{e256}";
pub const FILE: &str = "\u{e230}";
pub const WRENCH: &str = "\u{e5d4}"; // Tools
pub const LOCK_KEY: &str = "\u{e2fe}"; // Vault
pub const GEAR: &str = "\u{e270}"; // Settings
pub const TERMINAL: &str = "\u{eae8}"; // SSH (terminal-window)
pub const APP_WINDOW: &str = "\u{e5da}"; // RDP
pub const SCREENCAST: &str = "\u{e404}"; // VNC
pub const PLUG: &str = "\u{e946}"; // Serial
pub const MINUS: &str = "\u{e32a}"; // minimize
pub const SQUARE: &str = "\u{e45e}"; // maximize / restore
pub const X: &str = "\u{e4f6}"; // close
pub const SUN: &str = "\u{e472}"; // light theme
pub const MOON: &str = "\u{e330}"; // dark theme
pub const LIST: &str = "\u{e2f0}"; // menu
pub const PLUS: &str = "\u{e3d4}"; // new / add
pub const LINK: &str = "\u{e2e6}"; // add shared source
pub const SYNC: &str = "\u{e094}"; // sync now (arrows-clockwise)
pub const EXPORT: &str = "\u{eaf0}"; // back up / export
pub const IMPORT: &str = "\u{e20c}"; // import (download-simple)
pub const SEARCH: &str = "\u{e30c}"; // filter (magnifying-glass)
pub const EYE: &str = "\u{e220}";
pub const EYE_SLASH: &str = "\u{e224}";
pub const TRASH: &str = "\u{e4a6}";
pub const PENCIL: &str = "\u{e3b4}";
pub const COPY: &str = "\u{e1ca}";
pub const DOTS: &str = "\u{e208}"; // overflow menu (dots-three-vertical)

/// Icons offered in the session/folder appearance picker, as `(glyph, label)`.
/// Users pick one; the chosen glyph string is stored in the session/folder, and
/// renders via the bundled font. Existing emoji in saved data still render as-is.
pub const PICKER: &[(&str, &str)] = &[
    ("\u{e560}", "Desktop"),
    ("\u{e586}", "Laptop"),
    ("\u{e32e}", "Monitor"),
    ("\u{eae8}", "Terminal"),
    ("\u{e5da}", "Window"),
    ("\u{e2a0}", "Server"),
    ("\u{e1de}", "Database"),
    ("\u{e610}", "CPU"),
    ("\u{e29e}", "Drive"),
    ("\u{e288}", "Globe"),
    ("\u{e1aa}", "Cloud"),
    ("\u{e4ea}", "Wi-Fi"),
    ("\u{e0f2}", "Broadcast"),
    ("\u{e67c}", "Network"),
    ("\u{e946}", "Plug"),
    ("\u{e2de}", "Power"),
    ("\u{e2fa}", "Lock"),
    ("\u{e2fe}", "Key lock"),
    ("\u{e2d6}", "Key"),
    ("\u{e40a}", "Shield"),
    ("\u{e40c}", "Secure"),
    ("\u{e24a}", "Folder"),
    ("\u{e230}", "File"),
    ("\u{e46a}", "Star"),
    ("\u{e244}", "Flag"),
    ("\u{e478}", "Tag"),
    ("\u{e0ea}", "Bookmark"),
    ("\u{e0ce}", "Bell"),
    ("\u{e270}", "Gear"),
    ("\u{e5d4}", "Wrench"),
    ("\u{e3dc}", "Printer"),
    ("\u{e10e}", "Camera"),
    ("\u{e3b8}", "Phone"),
    ("\u{e214}", "Mail"),
    ("\u{e4c2}", "User"),
    ("\u{e4d6}", "Users"),
    ("\u{e102}", "Building"),
    ("\u{e2c2}", "Home"),
    ("\u{e1e6}", "Tablet"),
    ("\u{e278}", "Git"),
];
