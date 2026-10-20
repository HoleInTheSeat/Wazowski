//! SSH connections as terminal backends.
//!
//! [`connect`] establishes an interactive SSH session and returns an
//! [`SshBackend`] that plugs into [`wazowski_term::Terminal`] just like a local
//! shell does. The connection runs on its own tokio runtime in a background
//! thread; the terminal talks to it through the synchronous [`wazowski_term::Backend`]
//! interface while output flows back over a channel.
//!
//! Secrets are not read here. The caller resolves a session's stored
//! credentials (from the vault) into [`AuthMaterial`] and passes it in, keeping
//! this crate independent of how secrets are stored.

mod connection;
mod host_key;
mod keygen;
mod sftp;

pub use connection::{AuthMaterial, ConnectError, ConnectParams, SshBackend, connect};
pub use keygen::{GeneratedKey, KeyAlgo, generate, generate_ed25519};
pub use sftp::{FileEntry, Sftp};
pub use host_key::{HostKeyPolicy, UnknownHostKey, trust_host};
