//! Translation of egui key presses into the byte sequences an xterm sends.

use egui::{Key, Modifiers};

/// Bytes to send for a key press, or `None` if the key produces none
/// (printable keys arrive separately as text events).
pub(crate) fn key_to_bytes(key: Key, mods: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    // xterm's modifier parameter: 1 + shift + 2*alt + 4*ctrl.
    let param = 1 + mods.shift as u8 + 2 * mods.alt as u8 + 4 * mods.ctrl as u8;

    let cursor = |c: char| -> Vec<u8> {
        if param > 1 {
            format!("\x1b[1;{param}{c}")
        } else if app_cursor {
            format!("\x1bO{c}")
        } else {
            format!("\x1b[{c}")
        }
        .into_bytes()
    };
    let tilde = |n: u8| -> Vec<u8> {
        if param > 1 { format!("\x1b[{n};{param}~") } else { format!("\x1b[{n}~") }.into_bytes()
    };
    let ss3 = |c: char| -> Vec<u8> {
        if param > 1 { format!("\x1b[1;{param}{c}") } else { format!("\x1bO{c}") }.into_bytes()
    };
    let alt_prefixed = |bytes: &[u8]| -> Vec<u8> {
        if mods.alt { [b"\x1b", bytes].concat() } else { bytes.to_vec() }
    };

    let bytes = match key {
        Key::Enter => alt_prefixed(b"\r"),
        Key::Backspace if mods.ctrl => alt_prefixed(b"\x08"),
        Key::Backspace => alt_prefixed(b"\x7f"),
        Key::Tab if mods.shift => b"\x1b[Z".to_vec(),
        Key::Tab => b"\t".to_vec(),
        Key::Escape => b"\x1b".to_vec(),
        Key::ArrowUp => cursor('A'),
        Key::ArrowDown => cursor('B'),
        Key::ArrowRight => cursor('C'),
        Key::ArrowLeft => cursor('D'),
        Key::Home => cursor('H'),
        Key::End => cursor('F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => ss3('P'),
        Key::F2 => ss3('Q'),
        Key::F3 => ss3('R'),
        Key::F4 => ss3('S'),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        _ if mods.ctrl => alt_prefixed(&[ctrl_byte(key)?]),
        _ => return None,
    };
    Some(bytes)
}

/// The control character for Ctrl+`key`, e.g. Ctrl+A is 0x01.
fn ctrl_byte(key: Key) -> Option<u8> {
    let name = key.name();
    if name.len() == 1 && name.as_bytes()[0].is_ascii_alphabetic() {
        return Some(name.as_bytes()[0].to_ascii_lowercase() & 0x1f);
    }
    Some(match key {
        Key::Space | Key::Num2 => 0x00,
        Key::OpenBracket | Key::Num3 => 0x1b,
        Key::Backslash | Key::Num4 => 0x1c,
        Key::CloseBracket | Key::Num5 => 0x1d,
        Key::Num6 => 0x1e,
        Key::Minus | Key::Slash | Key::Num7 => 0x1f,
        Key::Num8 => 0x7f,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(key: Key, mods: Modifiers, app_cursor: bool) -> Vec<u8> {
        key_to_bytes(key, mods, app_cursor).unwrap()
    }

    #[test]
    fn control_letters() {
        assert_eq!(bytes(Key::A, Modifiers::CTRL, false), b"\x01");
        assert_eq!(bytes(Key::D, Modifiers::CTRL, false), b"\x04");
        assert_eq!(bytes(Key::Z, Modifiers::CTRL, false), b"\x1a");
        assert_eq!(bytes(Key::OpenBracket, Modifiers::CTRL, false), b"\x1b");
    }

    #[test]
    fn arrows_respect_cursor_mode_and_modifiers() {
        assert_eq!(bytes(Key::ArrowUp, Modifiers::NONE, false), b"\x1b[A");
        assert_eq!(bytes(Key::ArrowUp, Modifiers::NONE, true), b"\x1bOA");
        assert_eq!(bytes(Key::ArrowLeft, Modifiers::CTRL, true), b"\x1b[1;5D");
    }

    #[test]
    fn printable_keys_produce_nothing() {
        assert!(key_to_bytes(Key::A, Modifiers::NONE, false).is_none());
        assert!(key_to_bytes(Key::A, Modifiers::SHIFT, false).is_none());
    }
}
