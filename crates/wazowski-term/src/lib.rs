//! Terminal emulation widget for egui.
//!
//! Emulation is done by `alacritty_terminal`; this crate renders its grid with
//! egui and translates keyboard and mouse input. The byte stream behind a
//! terminal is abstracted as a [`Backend`] so the same widget serves local
//! shells, SSH channels, serial ports, and so on.

mod backend;
mod colors;
mod input;
mod pty;
mod terminal;
mod view;

pub use backend::{Backend, BackendEvent, TermSize};
pub use colors::Palette;
pub use pty::LocalPty;
pub use terminal::Terminal;
pub use view::TerminalView;
