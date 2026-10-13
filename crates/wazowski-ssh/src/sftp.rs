//! SFTP file operations over an established SSH session.
//!
//! The SFTP subsystem runs on the same connection as the shell: operations are
//! sent to the connection thread (see [`crate::connection`]), which opens the
//! subsystem lazily on first use and services each request on its own task so a
//! long transfer never blocks the terminal.
//!
//! [`Sftp`] exposes blocking helpers; call them from a worker thread, not the UI
//! thread, since each waits for the connection thread to reply.

use std::path::PathBuf;
use std::sync::mpsc::{SyncSender, sync_channel};

use tokio::sync::mpsc::UnboundedSender;

/// One entry in a remote directory listing.
#[derive(Clone, Debug)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    /// Modification time as a Unix timestamp, if the server reported one.
    pub mtime: Option<u32>,
}

/// A file operation to run on the connection thread.
pub(crate) enum SftpOp {
    Canonicalize(String),
    ListDir(String),
    Download { remote: String, local: PathBuf },
    Upload { local: PathBuf, remote: String },
    Mkdir(String),
    Remove { path: String, is_dir: bool },
    Rename { from: String, to: String },
}

/// The result of an [`SftpOp`].
pub(crate) enum SftpReply {
    Path(String),
    Entries(Vec<FileEntry>),
    Done,
}

/// A request plus where to send its result.
pub(crate) struct SftpRequest {
    pub op: SftpOp,
    pub reply: SyncSender<Result<SftpReply, String>>,
}

/// A handle for issuing SFTP operations on a live SSH session. Cloneable and
/// cheap; all clones share the one connection.
#[derive(Clone)]
pub struct Sftp {
    tx: UnboundedSender<SftpRequest>,
}

impl Sftp {
    pub(crate) fn new(tx: UnboundedSender<SftpRequest>) -> Self {
        Self { tx }
    }

    /// Sends an op and blocks until the connection thread replies.
    fn run(&self, op: SftpOp) -> Result<SftpReply, String> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(SftpRequest { op, reply: reply_tx })
            .map_err(|_| "the SSH session has closed".to_string())?;
        reply_rx.recv().map_err(|_| "the SSH session has closed".to_string())?
    }

    /// Resolves a path (e.g. `.` or `~`) to an absolute path on the server.
    pub fn canonicalize(&self, path: &str) -> Result<String, String> {
        match self.run(SftpOp::Canonicalize(path.to_owned()))? {
            SftpReply::Path(p) => Ok(p),
            _ => Err("unexpected reply".into()),
        }
    }

    /// Lists a remote directory, directories first then files, each alphabetical.
    pub fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, String> {
        match self.run(SftpOp::ListDir(path.to_owned()))? {
            SftpReply::Entries(mut entries) => {
                entries.sort_by(|a, b| {
                    b.is_dir
                        .cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                Ok(entries)
            }
            _ => Err("unexpected reply".into()),
        }
    }

    /// Downloads `remote` to the local path `local`.
    pub fn download(&self, remote: &str, local: PathBuf) -> Result<(), String> {
        self.expect_done(SftpOp::Download { remote: remote.to_owned(), local })
    }

    /// Uploads the local file `local` to `remote`.
    pub fn upload(&self, local: PathBuf, remote: &str) -> Result<(), String> {
        self.expect_done(SftpOp::Upload { local, remote: remote.to_owned() })
    }

    pub fn mkdir(&self, path: &str) -> Result<(), String> {
        self.expect_done(SftpOp::Mkdir(path.to_owned()))
    }

    pub fn remove(&self, path: &str, is_dir: bool) -> Result<(), String> {
        self.expect_done(SftpOp::Remove { path: path.to_owned(), is_dir })
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        self.expect_done(SftpOp::Rename { from: from.to_owned(), to: to.to_owned() })
    }

    fn expect_done(&self, op: SftpOp) -> Result<(), String> {
        match self.run(op)? {
            SftpReply::Done => Ok(()),
            _ => Err("unexpected reply".into()),
        }
    }
}
