//! Host key verification against the OpenSSH `known_hosts` file.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use russh::client;
use russh::keys::known_hosts::{
    check_known_hosts_path, known_host_keys_path, learn_known_hosts_path,
};
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

/// Records `host`/`port` as trusted in the user's `known_hosts` file.
///
/// For a *changed* host key this must first remove the stale entry: russh's
/// `learn_known_hosts_path` only appends, so leaving the old line in place makes
/// `check_known_hosts_path` keep reporting `KeyChanged` and the prompt loops
/// forever. We drop any recorded key for this host that differs from the new
/// one, then append the new key.
pub fn trust_host(host: &str, port: u16, key_openssh: &str) -> Result<()> {
    let key = PublicKey::from_openssh(key_openssh).context("invalid public key")?;
    let path = default_known_hosts()?;
    remove_stale_host_keys(host, port, &key, &path)
        .context("could not clear the old host key")?;
    learn_known_hosts_path(host, port, &key, &path).context("could not update known_hosts")
}

/// Removes any `known_hosts` lines recording a *different* key for this host, so
/// a replaced key doesn't keep triggering the "changed key" prompt. No-op when
/// the file is missing or has no stale entries. Handles hashed host entries by
/// reusing russh's host matcher ([`known_host_keys_path`]) to find the stale
/// keys, then rewrites the file dropping lines that carry those keys.
fn remove_stale_host_keys(
    host: &str,
    port: u16,
    new_key: &PublicKey,
    path: &std::path::Path,
) -> Result<()> {
    let existing = match known_host_keys_path(host, port, path) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let new_line = new_key.to_openssh().unwrap_or_default();
    // The `algo base64` form of each stale key (unique, so a substring match
    // against each file line reliably identifies the line to drop).
    let stale: Vec<String> = existing
        .into_iter()
        .filter_map(|(_, k)| k.to_openssh().ok())
        .filter(|s| !s.is_empty() && *s != new_line)
        .collect();
    if stale.is_empty() {
        return Ok(());
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let mut kept = String::new();
    for line in content.lines() {
        let is_comment = line.trim_start().starts_with('#');
        let drop = !is_comment && stale.iter().any(|s| line.contains(s.as_str()));
        if !drop {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    std::fs::write(path, kept)?;
    Ok(())
}

/// `~/.ssh/known_hosts`, the same file the `ssh` command uses.
pub(crate) fn default_known_hosts() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine the home directory")?;
    Ok(home.join(".ssh").join("known_hosts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two distinct, valid ed25519 public keys.
    const KEY_OLD: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const KEY_NEW: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";

    #[test]
    fn trusting_a_changed_key_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let old = PublicKey::from_openssh(KEY_OLD).unwrap();
        let new = PublicKey::from_openssh(KEY_NEW).unwrap();
        let (host, port) = ("example.test", 2222);

        learn_known_hosts_path(host, port, &old, &path).unwrap();
        // The new key is initially seen as a changed key.
        assert!(matches!(
            check_known_hosts_path(host, port, &new, &path),
            Err(keys::Error::KeyChanged { .. })
        ));

        // Replace it, the way trust_host does for a changed key.
        remove_stale_host_keys(host, port, &new, &path).unwrap();
        learn_known_hosts_path(host, port, &new, &path).unwrap();

        // Now the new key is trusted and the old one is gone (no more loop).
        assert_eq!(check_known_hosts_path(host, port, &new, &path).unwrap(), true);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains(KEY_OLD.split(' ').nth(1).unwrap()));
        assert!(content.contains(KEY_NEW.split(' ').nth(1).unwrap()));
    }

    #[test]
    fn trusting_an_unchanged_first_key_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let new = PublicKey::from_openssh(KEY_NEW).unwrap();
        // No prior entry: removal is a no-op, learn adds it.
        remove_stale_host_keys("fresh.test", 22, &new, &path).unwrap();
        learn_known_hosts_path("fresh.test", 22, &new, &path).unwrap();
        assert_eq!(check_known_hosts_path("fresh.test", 22, &new, &path).unwrap(), true);
    }
}
