//! Host key verification against the OpenSSH `known_hosts` file.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use russh::client;
use russh::keys::known_hosts::{check_known_hosts_path, learn_known_hosts_path};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{self, PublicKeyOrCertificate};

/// What to do when the server's key is not already in `known_hosts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Reject unknown hosts; the caller prompts the user and may add the host.
    Strict,
    /// Add an unknown host's key to `known_hosts` and continue (trust on first use).
    AcceptNew,
}

/// Details of an unknown or changed host key, surfaced so the UI can prompt.
#[derive(Clone, Debug)]
pub struct UnknownHostKey {
    pub host: String,
    pub port: u16,
    /// e.g. `SHA256:abc...`.
    pub fingerprint: String,
    /// The key's algorithm, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// The key in OpenSSH single-line form, to hand back to [`trust_host`].
    pub key_openssh: String,
}

/// The verdict reached while verifying the server key.
#[derive(Clone, Debug, Default)]
pub(crate) enum Verdict {
    #[default]
    Pending,
    /// Key is in `known_hosts` (or was just learned under `AcceptNew`).
    Trusted,
    /// Key is not known; connection was refused.
    Unknown(UnknownHostKey),
    /// A different key is recorded for this host: possible attack.
    Changed(UnknownHostKey),
}

/// russh client handler that verifies the server key and records the outcome.
pub(crate) struct Handler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: PathBuf,
    verdict: Arc<Mutex<Verdict>>,
}

impl Handler {
    pub(crate) fn new(
        host: String,
        port: u16,
        policy: HostKeyPolicy,
        known_hosts: PathBuf,
        verdict: Arc<Mutex<Verdict>>,
    ) -> Self {
        Self { host, port, policy, known_hosts, verdict }
    }

    fn describe(&self, key: &PublicKey) -> UnknownHostKey {
        UnknownHostKey {
            host: self.host.clone(),
            port: self.port,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            algorithm: key.algorithm().to_string(),
            key_openssh: key.to_openssh().unwrap_or_default(),
        }
    }
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let verdict = match check_known_hosts_path(&self.host, self.port, &key, &self.known_hosts) {
            Ok(true) => Verdict::Trusted,
            Ok(false) => match self.policy {
                HostKeyPolicy::AcceptNew => {
                    learn_known_hosts_path(&self.host, self.port, &key, &self.known_hosts)
                        .map_err(russh::Error::from)?;
                    Verdict::Trusted
                }
                HostKeyPolicy::Strict => Verdict::Unknown(self.describe(&key)),
            },
            Err(keys::Error::KeyChanged { .. }) => Verdict::Changed(self.describe(&key)),
            Err(e) => return Err(e.into()),
        };
        let accept = matches!(verdict, Verdict::Trusted);
        *self.verdict.lock().expect("verdict mutex poisoned") = verdict;
        Ok(accept)
    }
}

/// Records `host`/`port` as trusted by appending its key to the user's
/// `known_hosts` file. Called after the user accepts an unknown-host prompt.
pub fn trust_host(host: &str, port: u16, key_openssh: &str) -> Result<()> {
    let key = PublicKey::from_openssh(key_openssh).context("invalid public key")?;
    learn_known_hosts_path(host, port, &key, default_known_hosts()?)
        .context("could not update known_hosts")
}

/// `~/.ssh/known_hosts`, the same file the `ssh` command uses.
pub(crate) fn default_known_hosts() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine the home directory")?;
    Ok(home.join(".ssh").join("known_hosts"))
}
