//! Shared models and services for Wazowski: the encrypted secret vault, and
//! (in later phases) session definitions and configuration.

pub mod session;
pub mod vault;

pub use session::{Auth, FolderStyle, Protocol, Session, SessionStore, VncQuality};
pub use vault::{Secret, Vault, VaultError};
