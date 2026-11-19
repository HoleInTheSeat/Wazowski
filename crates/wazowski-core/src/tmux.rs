//! tmux session management.
//!
//! This module knows how to *ask* tmux about its sessions and how to *parse*
//! the answer. The parsing is deliberately separated from the running so that
//! the same logic serves both a local tmux (invoked with [`std::process::Command`])
//! and, later, a tmux on a remote host reached over an SSH exec channel — the
//! `-F` output format is identical either way, so only the transport differs.
//!
//! The format string ([`LIST_FORMAT`]) packs each session onto one line with a
//! unit-separator (`U+001F`) between fields, a byte that cannot occur in a
//! session name, so names containing spaces or tabs survive the round trip.

use std::process::Command;

/// Field separator inside a single session's line. `U+001F` (unit separator) is
/// a control byte tmux will never put in a session name, so splitting on it is
/// unambiguous even when names contain whitespace.
const SEP: char = '\u{1f}';

/// The `tmux list-sessions -F` format: one line per session, fields separated by
/// [`SEP`]. Kept in sync with the field order parsed by [`parse_sessions`].
pub const LIST_FORMAT: &str =
    "#{session_name}\u{1f}#{session_windows}\u{1f}#{session_attached}\u{1f}#{session_created}";

/// A tmux session as reported by `list-sessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmuxSession {
    /// The session name (the `-t` target), e.g. `main`.
    pub name: String,
    /// Number of windows in the session.
    pub windows: u32,
    /// Whether at least one client is attached.
    pub attached: bool,
    /// Creation time as a Unix timestamp, if tmux reported a parseable one.
    pub created: Option<i64>,
}

/// Something went wrong talking to tmux.
#[derive(Debug, thiserror::Error)]
pub enum TmuxError {
    /// The `tmux` binary could not be found or run.
    #[error("tmux is not installed or not on PATH")]
    NotInstalled,
    /// tmux ran but exited with an error (other than "no server running").
    #[error("tmux: {0}")]
    Failed(String),
    /// The command could not be launched for some other reason.
    #[error("could not run tmux: {0}")]
    Io(String),
}

/// Builds the argv for `list-sessions`. Shared by the local and (future) remote
/// callers so both get exactly the same format.
pub fn list_args() -> Vec<String> {
    vec!["list-sessions".into(), "-F".into(), LIST_FORMAT.into()]
}

/// Builds the argv to kill (terminate) a session by name.
pub fn kill_args(name: &str) -> Vec<String> {
    vec!["kill-session".into(), "-t".into(), name.into()]
}

/// Builds the argv to rename a session.
pub fn rename_args(old: &str, new: &str) -> Vec<String> {
    vec!["rename-session".into(), "-t".into(), old.into(), new.into()]
}

/// Builds the argv to create a new *detached* session with the given name.
pub fn new_detached_args(name: &str) -> Vec<String> {
    vec!["new-session".into(), "-d".into(), "-s".into(), name.into()]
}

/// Builds the argv to attach a client to an existing session. This is the
/// command a PTY runs to put a live tmux on screen.
pub fn attach_args(name: &str) -> Vec<String> {
    vec!["attach-session".into(), "-t".into(), name.into()]
}

/// Parses the stdout of `tmux list-sessions -F LIST_FORMAT` into sessions.
///
/// Lines that are blank or malformed (too few fields) are skipped rather than
/// failing the whole listing — a single odd line should never hide every other
/// session. `session_attached` is tmux's count of attached clients, so any
/// non-zero value means "attached".
pub fn parse_sessions(stdout: &str) -> Vec<TmuxSession> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                return None;
            }
            let mut fields = line.split(SEP);
            let name = fields.next()?.to_string();
            if name.is_empty() {
                return None;
            }
            let windows = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let attached = fields.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) > 0;
            let created = fields.next().and_then(|s| s.parse().ok());
            Some(TmuxSession { name, windows, attached, created })
        })
        .collect()
}

/// Distinguishes tmux's "there is simply no server running yet" message (which
/// we treat as an empty list) from a real failure.
fn is_no_server(stderr: &str) -> bool {
    stderr.to_lowercase().contains("no server running")
}

/// Runs `tmux <args>` locally and returns its stdout on success.
///
/// `no_server_ok` controls what happens when tmux reports that no server is
/// running: for a listing that means "zero sessions" (`Ok("")`), but for an
/// action like kill/rename it is a genuine failure.
fn run_local(args: &[String], no_server_ok: bool) -> Result<String, TmuxError> {
    let output = Command::new("tmux").args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            TmuxError::NotInstalled
        } else {
            TmuxError::Io(e.to_string())
        }
    })?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if no_server_ok && is_no_server(&stderr) {
        return Ok(String::new());
    }
    Err(TmuxError::Failed(stderr.trim().to_string()))
}

/// Whether a local `tmux` binary is available, and its version banner if so
/// (e.g. `"tmux 3.3a"`). Returns `None` when tmux is not installed.
pub fn detect_local() -> Option<String> {
    let output = Command::new("tmux").arg("-V").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let banner = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!banner.is_empty()).then_some(banner)
}

/// Lists the local tmux sessions. An absent server yields an empty list.
pub fn local_sessions() -> Result<Vec<TmuxSession>, TmuxError> {
    Ok(parse_sessions(&run_local(&list_args(), true)?))
}

/// Terminates a local session by name.
pub fn local_kill(name: &str) -> Result<(), TmuxError> {
    run_local(&kill_args(name), false).map(|_| ())
}

/// Renames a local session.
pub fn local_rename(old: &str, new: &str) -> Result<(), TmuxError> {
    run_local(&rename_args(old, new), false).map(|_| ())
}

/// Creates a new detached local session.
pub fn local_new_detached(name: &str) -> Result<(), TmuxError> {
    run_local(&new_detached_args(name), false).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(name: &str, windows: &str, attached: &str, created: &str) -> String {
        format!("{name}{SEP}{windows}{SEP}{attached}{SEP}{created}")
    }

    #[test]
    fn parses_a_typical_listing() {
        let out = format!(
            "{}\n{}\n",
            line("main", "3", "1", "1700000000"),
            line("deploy", "1", "0", "1700000500"),
        );
        let sessions = parse_sessions(&out);
        assert_eq!(
            sessions,
            vec![
                TmuxSession {
                    name: "main".into(),
                    windows: 3,
                    attached: true,
                    created: Some(1_700_000_000),
                },
                TmuxSession {
                    name: "deploy".into(),
                    windows: 1,
                    attached: false,
                    created: Some(1_700_000_500),
                },
            ]
        );
    }

    #[test]
    fn attached_counts_above_one_are_still_attached() {
        let sessions = parse_sessions(&line("shared", "2", "3", "0"));
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].attached);
    }

    #[test]
    fn names_with_spaces_survive() {
        let sessions = parse_sessions(&line("my project", "1", "0", "1"));
        assert_eq!(sessions[0].name, "my project");
    }

    #[test]
    fn blank_and_malformed_lines_are_skipped() {
        let out = format!("\n{}\n\n", line("ok", "1", "0", "1"));
        let sessions = parse_sessions(&out);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "ok");
    }

    #[test]
    fn missing_trailing_fields_default_gracefully() {
        // Only a name, no separators at all.
        let sessions = parse_sessions("lonely");
        assert_eq!(
            sessions,
            vec![TmuxSession {
                name: "lonely".into(),
                windows: 0,
                attached: false,
                created: None,
            }]
        );
    }

    #[test]
    fn empty_output_is_no_sessions() {
        assert!(parse_sessions("").is_empty());
        assert!(parse_sessions("\n\n").is_empty());
    }

    #[test]
    fn no_server_message_is_recognized() {
        assert!(is_no_server("no server running on /tmp/tmux-1000/default"));
        assert!(is_no_server("error connecting to /tmp/x (No server running)"));
        assert!(!is_no_server("session not found: main"));
    }

    #[test]
    fn arg_builders_are_well_formed() {
        assert_eq!(list_args(), vec!["list-sessions", "-F", LIST_FORMAT]);
        assert_eq!(kill_args("main"), vec!["kill-session", "-t", "main"]);
        assert_eq!(rename_args("a", "b"), vec!["rename-session", "-t", "a", "b"]);
        assert_eq!(new_detached_args("x"), vec!["new-session", "-d", "-s", "x"]);
        assert_eq!(attach_args("x"), vec!["attach-session", "-t", "x"]);
    }
}
