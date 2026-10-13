//! Shared models and services for Wazowski: the encrypted secret vault, and
//! (in later phases) session definitions and configuration.

pub mod vault;

pub use vault::{Secret, Vault, VaultError};
