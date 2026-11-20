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

/// Builds the argv to split the active window of a session. `horizontal` splits
/// left/right (tmux `-h`, panes side by side), otherwise top/bottom (`-v`).
/// Targeting the session by name hits its active window and pane — where an
/// attached client is looking — so the split lands where the user is.
pub fn split_args(name: &str, horizontal: bool) -> Vec<String> {
    let flag = if horizontal { "-h" } else { "-v" };
    vec!["split-window".into(), flag.into(), "-t".into(), name.into()]
}

/// Builds the argv to turn a session's pane synchronization on or off (tmux's
/// `synchronize-panes`, which mirrors typed input to every pane in the window).
pub fn sync_panes_args(name: &str, on: bool) -> Vec<String> {
    let val = if on { "on" } else { "off" };
    vec![
        "set-window-option".into(),
        "-t".into(),
        name.into(),
        "synchronize-panes".into(),
        val.into(),
    ]
}

/// Wraps a string in single quotes for safe use as one argument in a remote
/// shell command (SSH exec runs the command through the login shell). Embedded
/// single quotes are escaped the POSIX way: `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The remote command to list sessions — the same `-F` format as the local
/// path, quoted for the remote shell.
pub fn remote_list_command() -> String {
    format!("tmux list-sessions -F {}", shell_quote(LIST_FORMAT))
}

/// The remote command to kill (terminate) a session.
pub fn remote_kill_command(name: &str) -> String {
    format!("tmux kill-session -t {}", shell_quote(name))
}

/// The remote command to rename a session.
pub fn remote_rename_command(old: &str, new: &str) -> String {
    format!("tmux rename-session -t {} {}", shell_quote(old), shell_quote(new))
}

/// The remote command to create a new detached session.
pub fn remote_new_command(name: &str) -> String {
    format!("tmux new-session -d -s {}", shell_quote(name))
}

/// The remote command to attach to a session, typed into the SSH shell (no
/// trailing newline — the caller adds the Enter that runs it).
pub fn remote_attach_command(name: &str) -> String {
    format!("tmux attach -t {}", shell_quote(name))
}

/// The remote command to detach the SSH shell from tmux entirely, typed into
/// the shell — drops the client back to the plain login shell. A harmless no-op
/// (prints a short error) if the shell isn't inside tmux. No trailing newline —
/// the caller adds the Enter that runs it.
///
/// Note: `detach-client` run as a command has no "current client", so it can
/// detach *every* client attached to the session. To detach only the local
/// client, send the prefix + `d` keystroke instead — see
/// [`remote_prefix_query_command`] and [`prefix_control_byte`].
pub fn remote_detach_command() -> String {
    "tmux detach-client".to_owned()
}

/// The remote command that prints the session's tmux prefix key (e.g. `C-b`),
/// so a detach can be sent as that exact keystroke rather than a command.
pub fn remote_prefix_query_command() -> String {
    "tmux show-options -gv prefix".to_owned()
}

/// Builds the argv that prints the tmux prefix key (e.g. `C-b`) — the local
/// equivalent of [`remote_prefix_query_command`].
pub fn prefix_query_args() -> Vec<String> {
    vec!["show-options".into(), "-gv".into(), "prefix".into()]
}

/// Parses a tmux prefix key as printed by `show-options` (e.g. `C-b`, `C-a`)
/// into the control byte a terminal sends for it: `C-b` → 0x02, `C-a` → 0x01.
/// Falls back to the default prefix `C-b` (0x02) for anything unrecognised.
pub fn prefix_control_byte(s: &str) -> u8 {
    const DEFAULT: u8 = 0x02; // C-b
    let s = s.trim();
    let rest = s.strip_prefix("C-").or_else(|| s.strip_prefix("c-"));
    match rest.and_then(|r| r.chars().next()) {
        Some(c) if c.is_ascii_alphabetic() => (c.to_ascii_lowercase() as u8) & 0x1f,
        _ => DEFAULT,
    }
}

/// The remote command to move the SSH shell's view to a session, typed into the
/// shell. Works whether or not the shell is already inside tmux: if it is,
/// `switch-client` re-points the existing client without the "sessions should be
/// nested" warning; if it isn't, that call fails quietly and a plain `attach`
/// runs instead. No trailing newline — the caller adds the Enter that runs it.
pub fn remote_switch_or_attach_command(name: &str) -> String {
    let t = shell_quote(name);
    format!("tmux switch-client -t {t} 2>/dev/null || tmux attach -t {t}")
}

/// Builds the argv to list the tmux server's attached clients as
/// `"<activity> <session>"` lines — used to discover which session this
/// connection is attached to (e.g. when a `.bashrc` auto-attaches on login).
pub fn list_clients_args() -> Vec<String> {
    vec!["list-clients".into(), "-F".into(), "#{client_activity} #{client_session}".into()]
}

/// The remote command form of [`list_clients_args`].
pub fn remote_list_clients_command() -> String {
    format!("tmux list-clients -F {}", shell_quote("#{client_activity} #{client_session}"))
}

/// Picks the most-recently-active client's session name from `list-clients`
/// output (one `"<activity> <session>"` line per client). `None` when there are
/// no attached clients — i.e. nothing is in tmux. Session names may contain
/// spaces (only the leading activity field is split off). With more than one
/// client the newest activity wins, a best-effort guess at "this one".
pub fn newest_client_session(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (activity, session) = line.split_once(' ').unwrap_or(("0", line));
            let session = session.trim();
            if session.is_empty() {
                return None;
            }
            Some((activity.trim().parse::<u64>().unwrap_or(0), session.to_string()))
        })
        .max_by_key(|(activity, _)| *activity)
        .map(|(_, session)| session)
}

/// The remote command to split the active window of a session, run on the SSH
/// exec side channel (not typed into the session), so it never injects keys into
/// a pane. tmux updates every attached client, so the split appears live.
pub fn remote_split_command(name: &str, horizontal: bool) -> String {
    let flag = if horizontal { "-h" } else { "-v" };
    format!("tmux split-window {flag} -t {}", shell_quote(name))
}

/// The remote command to toggle a session's `synchronize-panes` on or off, run
/// on the SSH exec side channel (not typed into the session).
pub fn remote_sync_panes_command(name: &str, on: bool) -> String {
    let val = if on { "on" } else { "off" };
    format!("tmux set-window-option -t {} synchronize-panes {val}", shell_quote(name))
}

/// Interprets the result of a remote `list-sessions` (its stdout, stderr, and
/// exit status) into sessions, treating tmux's "no server running" as an empty
/// list rather than an error — matching the local path's behaviour.
pub fn interpret_list(stdout: &str, stderr: &str, exit: u32) -> Result<Vec<TmuxSession>, String> {
    if exit == 0 {
        return Ok(parse_sessions(stdout));
    }
    if is_no_server(stderr) {
        return Ok(Vec::new());
    }
    let msg = stderr.trim();
    Err(if msg.is_empty() { format!("tmux exited with status {exit}") } else { msg.to_string() })
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

/// Splits the active window of a local session (see [`split_args`]).
pub fn local_split(name: &str, horizontal: bool) -> Result<(), TmuxError> {
    run_local(&split_args(name, horizontal), false).map(|_| ())
}

/// Toggles `synchronize-panes` on a local session's active window.
pub fn local_sync_panes(name: &str, on: bool) -> Result<(), TmuxError> {
    run_local(&sync_panes_args(name, on), false).map(|_| ())
}

/// Reads the local tmux server's prefix key (e.g. `C-b`); empty when there's no
/// server. Feed the result to [`prefix_control_byte`].
pub fn local_prefix() -> Result<String, TmuxError> {
    run_local(&prefix_query_args(), true)
}

/// The session a local tmux client is attached to (newest-active one), or `None`
/// when nothing is attached. Used to discover a `.bashrc` auto-attach locally.
pub fn local_attached_session() -> Option<String> {
    run_local(&list_clients_args(), true).ok().and_then(|o| newest_client_session(&o))
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
    fn shell_quoting_wraps_and_escapes() {
        assert_eq!(shell_quote("main"), "'main'");
        assert_eq!(shell_quote("my session"), "'my session'");
        // A single quote becomes '\'' (close, escaped quote, reopen).
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn remote_commands_are_quoted() {
        assert_eq!(remote_kill_command("main"), "tmux kill-session -t 'main'");
        assert_eq!(remote_rename_command("a", "b"), "tmux rename-session -t 'a' 'b'");
        assert_eq!(remote_new_command("x"), "tmux new-session -d -s 'x'");
        assert_eq!(remote_attach_command("x"), "tmux attach -t 'x'");
        assert_eq!(remote_detach_command(), "tmux detach-client");
        assert_eq!(remote_prefix_query_command(), "tmux show-options -gv prefix");
        assert_eq!(
            remote_switch_or_attach_command("x"),
            "tmux switch-client -t 'x' 2>/dev/null || tmux attach -t 'x'"
        );
        assert!(remote_list_command().starts_with("tmux list-sessions -F '"));
        assert_eq!(remote_split_command("x", true), "tmux split-window -h -t 'x'");
        assert_eq!(remote_split_command("x", false), "tmux split-window -v -t 'x'");
        assert_eq!(
            remote_sync_panes_command("x", true),
            "tmux set-window-option -t 'x' synchronize-panes on"
        );
        assert_eq!(
            remote_sync_panes_command("x", false),
            "tmux set-window-option -t 'x' synchronize-panes off"
        );
    }

    #[test]
    fn split_and_sync_args_build() {
        assert_eq!(split_args("s", true), ["split-window", "-h", "-t", "s"]);
        assert_eq!(split_args("s", false), ["split-window", "-v", "-t", "s"]);
        assert_eq!(
            sync_panes_args("s", true),
            ["set-window-option", "-t", "s", "synchronize-panes", "on"]
        );
        assert_eq!(
            sync_panes_args("s", false),
            ["set-window-option", "-t", "s", "synchronize-panes", "off"]
        );
    }

    #[test]
    fn newest_client_session_picks_most_recent() {
        assert_eq!(newest_client_session(""), None);
        assert_eq!(newest_client_session("\n  \n"), None);
        assert_eq!(newest_client_session("1700000000 main"), Some("main".into()));
        // Two clients: the newer activity wins.
        let out = "1700000000 old\n1700000500 current\n";
        assert_eq!(newest_client_session(out), Some("current".into()));
        // Session names may contain spaces.
        assert_eq!(newest_client_session("1700000000 my project"), Some("my project".into()));
    }

    #[test]
    fn prefix_control_byte_maps_and_falls_back() {
        assert_eq!(prefix_control_byte("C-b"), 0x02);
        assert_eq!(prefix_control_byte("C-a"), 0x01);
        assert_eq!(prefix_control_byte("C-b\n"), 0x02); // trailing newline
        assert_eq!(prefix_control_byte("c-a"), 0x01); // lenient case
        assert_eq!(prefix_control_byte(""), 0x02); // empty → default C-b
        assert_eq!(prefix_control_byte("None"), 0x02); // unexpected → default
    }

    #[test]
    fn interpret_list_handles_success_empty_and_error() {
        let ok = line("main", "1", "0", "1");
        assert_eq!(interpret_list(&ok, "", 0).unwrap().len(), 1);
        // No server running → empty list, not an error.
        assert_eq!(interpret_list("", "no server running on ...", 1).unwrap().len(), 0);
        // A real error surfaces the stderr.
        assert_eq!(
            interpret_list("", "some other failure", 1).unwrap_err(),
            "some other failure"
        );
        // Non-zero with no stderr still errors.
        assert!(interpret_list("", "", 2).is_err());
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
