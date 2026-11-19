//! One-shot command execution over an established SSH session.
//!
//! Unlike the interactive shell (which streams over its own channel) or SFTP
//! (its own subsystem), an exec runs a single command on a fresh session
//! channel, collects its output, and returns. It shares the same connection as
//! the shell — the connection thread services exec requests concurrently, so a
//! slow command never blocks the terminal.
//!
//! [`Exec`] exposes a blocking [`Exec::run`]; call it from a worker thread, not
//! the UI thread, since it waits for the connection thread to reply.

use std::sync::mpsc::{SyncSender, sync_channel};

use tokio::sync::mpsc::UnboundedSender;

/// The captured result of a remote command.
#[derive(Clone, Debug)]
pub struct ExecOutput {
    /// Standard output, decoded lossily as UTF-8.
    pub stdout: String,
    /// Standard error, decoded lossily as UTF-8.
    pub stderr: String,
    /// The command's exit status (0 on success).
    pub exit: u32,
}

/// A request to run `command`, plus where to send its result.
pub(crate) struct ExecRequest {
    pub command: String,
    pub reply: SyncSender<Result<ExecOutput, String>>,
}

/// A handle for running one-shot commands on a live SSH session. Cloneable and
/// cheap; all clones share the one connection.
#[derive(Clone)]
pub struct Exec {
    tx: UnboundedSender<ExecRequest>,
}

impl Exec {
    pub(crate) fn new(tx: UnboundedSender<ExecRequest>) -> Self {
        Self { tx }
    }

    /// Runs `command` on the server and blocks until it finishes, returning its
    /// captured output. Call from a worker thread.
    pub fn run(&self, command: &str) -> Result<ExecOutput, String> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(ExecRequest { command: command.to_owned(), reply: reply_tx })
            .map_err(|_| "the SSH session has closed".to_string())?;
        reply_rx.recv().map_err(|_| "the SSH session has closed".to_string())?
    }
}
