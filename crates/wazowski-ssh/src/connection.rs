use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use russh::client::{self, Handle};
#[cfg(unix)]
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::HashAlg;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, decode_secret_key};
use russh::{ChannelMsg, Disconnect};
use tokio::io::AsyncWriteExt;
use std::sync::Arc as StdArc;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use wazowski_term::{Backend, BackendEvent, TermSize};

use crate::host_key::{self, Handler, HostKeyPolicy, UnknownHostKey, Verdict};
use crate::sftp::{FileEntry, Sftp, SftpOp, SftpReply, SftpRequest};

/// Resolved credentials for a connection. The caller fetches these from the
/// vault (or the agent) before connecting, so this crate never touches secrets at rest.
#[derive(Clone)]
pub enum AuthMaterial {
    /// Try every key currently loaded in the SSH agent.
    Agent,
    /// A password.
    Password(String),
    /// A private key in PEM/OpenSSH form, with an optional passphrase.
    Key { pem: String, passphrase: Option<String> },
}

/// Everything needed to open a session.
#[derive(Clone)]
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMaterial,
    pub policy: HostKeyPolicy,
    /// Initial terminal size.
    pub size: TermSize,
    /// Path to the `known_hosts` file. `None` uses `~/.ssh/known_hosts`.
    pub known_hosts: Option<PathBuf>,
    /// Also offer legacy key exchanges, ciphers, and MACs (e.g. SHA-1 KEX,
    /// CBC ciphers) so old equipment such as HPE/ProCurve switches can connect.
    /// Off by default; these algorithms are weak and should be opt-in per host.
    pub legacy_algorithms: bool,
}

/// Why a connection attempt failed, in a form the UI can act on.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("the server's host key is not known")]
    UnknownHost(UnknownHostKey),
    #[error("the server's host key has changed, which could indicate an attack")]
    HostKeyChanged(UnknownHostKey),
    #[error("authentication failed")]
    AuthFailed,
    #[error("could not reach {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: anyhow::Error,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Commands sent from the terminal (GUI thread) to the connection task.
enum Cmd {
    Data(Vec<u8>),
    Resize(TermSize),
}

/// An established SSH session, usable as a terminal backend.
pub struct SshBackend {
    /// `Option` so [`Drop`] can drop the sender before joining the thread:
    /// closing the channel is what tells the event loop to shut down.
    cmds: Option<UnboundedSender<Cmd>>,
    /// Sender for SFTP requests over the same connection.
    sftp: UnboundedSender<SftpRequest>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SshBackend {
    /// Returns a handle for SFTP operations on this session. The SFTP subsystem
    /// is opened lazily on first use.
    pub fn sftp(&self) -> Sftp {
        Sftp::new(self.sftp.clone())
    }
}

impl Backend for SshBackend {
    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let closed = || std::io::Error::new(std::io::ErrorKind::BrokenPipe, "ssh session closed");
        self.cmds
            .as_ref()
            .ok_or_else(closed)?
            .send(Cmd::Data(data.to_vec()))
            .map_err(|_| closed())
    }

    fn resize(&mut self, size: TermSize) -> std::io::Result<()> {
        // A closed session simply means nothing to resize; ignore the error.
        if let Some(cmds) = &self.cmds {
            let _ = cmds.send(Cmd::Resize(size));
        }
        Ok(())
    }
}

impl Drop for SshBackend {
    fn drop(&mut self) {
        // Drop the sender first: that closes the command channel, so the event
        // loop's `recv()` returns `None` and the runtime thread can finish.
        // Joining while still holding the sender would deadlock.
        self.cmds.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Opens an SSH session. Blocks until the session is established or fails, so
/// call it from a worker thread rather than the UI thread.
pub fn connect(
    params: ConnectParams,
    wake: impl Fn() + Send + 'static,
) -> Result<(SshBackend, Receiver<BackendEvent>), ConnectError> {
    let (out_tx, out_rx) = std::sync::mpsc::sync_channel(256);
    let (cmd_tx, cmd_rx) = unbounded_channel();
    let (sftp_tx, sftp_rx) = unbounded_channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let thread = thread::Builder::new()
        .name(format!("ssh-{}", params.host))
        .spawn(move || {
            let runtime = match Builder::new_multi_thread().worker_threads(2).enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(ConnectError::Other(e.into())));
                    return;
                }
            };
            runtime.block_on(session_task(params, wake, out_tx, cmd_rx, sftp_rx, ready_tx));
        })
        .map_err(|e| ConnectError::Other(e.into()))?;

    // Wait for the task to report whether the handshake succeeded.
    match ready_rx.recv() {
        Ok(Ok(())) => {
            Ok((SshBackend { cmds: Some(cmd_tx), sftp: sftp_tx, thread: Some(thread) }, out_rx))
        }
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        // The task panicked or dropped the sender before reporting.
        Err(_) => {
            let _ = thread.join();
            Err(ConnectError::Other(anyhow!("the SSH task exited unexpectedly")))
        }
    }
}

/// Runs on the connection thread: connect, authenticate, open a shell, then
/// pump data until the channel closes or the backend is dropped.
async fn session_task(
    params: ConnectParams,
    wake: impl Fn() + Send,
    out: SyncSender<BackendEvent>,
    cmds: UnboundedReceiver<Cmd>,
    sftp: UnboundedReceiver<SftpRequest>,
    ready: std::sync::mpsc::Sender<Result<(), ConnectError>>,
) {
    match establish(&params).await {
        Ok(handle) => {
            // Tell the caller we are connected before entering the loop.
            if ready.send(Ok(())).is_err() {
                return;
            }
            if let Err(e) = pump(handle, params, &wake, &out, cmds, sftp).await {
                log::warn!("ssh session ended: {e:#}");
            }
            let _ = out.send(BackendEvent::Exited);
            wake();
        }
        Err(e) => {
            let _ = ready.send(Err(e));
        }
    }
}

/// How long the whole connect-and-authenticate handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Connects and authenticates, returning the session handle. Bounded by
/// [`HANDSHAKE_TIMEOUT`] so a stalled handshake can't hang the caller forever.
async fn establish(params: &ConnectParams) -> Result<Handle<Handler>, ConnectError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, establish_inner(params)).await {
        Ok(result) => result,
        Err(_) => Err(ConnectError::Connect {
            host: params.host.clone(),
            port: params.port,
            source: anyhow!("timed out after {}s", HANDSHAKE_TIMEOUT.as_secs()),
        }),
    }
}

async fn establish_inner(params: &ConnectParams) -> Result<Handle<Handler>, ConnectError> {
    // Old gear (ProCurve) offers 2048-bit groups for group-exchange KEX, below
    // russh's default 3072-bit minimum, so widen the accepted range in legacy mode.
    let gex = if params.legacy_algorithms {
        client::GexParams::new(2048, 2048, 8192).map_err(|e| ConnectError::Other(anyhow!(e)))?
    } else {
        client::GexParams::default()
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        preferred: preferred_algorithms(params.legacy_algorithms),
        gex,
        ..Default::default()
    });

    let known_hosts = match &params.known_hosts {
        Some(path) => path.clone(),
        None => host_key::default_known_hosts().map_err(ConnectError::Other)?,
    };
    let verdict = Arc::new(Mutex::new(Verdict::Pending));
    let handler = Handler::new(
        params.host.clone(),
        params.port,
        params.policy,
        known_hosts,
        verdict.clone(),
    );

    log::info!(
        "connecting to {}:{}{}",
        params.host,
        params.port,
        if params.legacy_algorithms { " (legacy algorithms enabled)" } else { "" }
    );
    let mut handle = match client::connect(config, (params.host.as_str(), params.port), handler)
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            // A refused connection is usually the host key verdict; surface that if so.
            return Err(match std::mem::take(&mut *verdict.lock().unwrap()) {
                Verdict::Unknown(info) => ConnectError::UnknownHost(info),
                Verdict::Changed(info) => ConnectError::HostKeyChanged(info),
                _ => ConnectError::Connect {
                    host: params.host.clone(),
                    port: params.port,
                    source: e.into(),
                },
            });
        }
    };

    log::info!("transport established; authenticating as {}", params.username);
    authenticate(&mut handle, &params.username, &params.auth).await?;
    log::info!("authenticated; opening shell");
    Ok(handle)
}

/// Performs authentication by the chosen method.
async fn authenticate(
    handle: &mut Handle<Handler>,
    username: &str,
    auth: &AuthMaterial,
) -> Result<(), ConnectError> {
    let ok = match auth {
        AuthMaterial::Password(password) => handle
            .authenticate_password(username, password.clone())
            .await
            .map_err(to_other)?
            .success(),
        AuthMaterial::Key { pem, passphrase } => {
            let key = decode_secret_key(pem, passphrase.as_deref())
                .map_err(|e| ConnectError::Other(anyhow!("could not load the private key: {e}")))?;
            authenticate_key(handle, username, key).await?
        }
        AuthMaterial::Agent => authenticate_agent(handle, username).await?,
    };
    if ok { Ok(()) } else { Err(ConnectError::AuthFailed) }
}

/// Authenticates with a single private key, asking the server which RSA hash to
/// use when the key is RSA.
async fn authenticate_key(
    handle: &mut Handle<Handler>,
    username: &str,
    key: PrivateKey,
) -> Result<bool, ConnectError> {
    let hash = rsa_hash(handle, &key).await?;
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    Ok(handle.authenticate_publickey(username, key).await.map_err(to_other)?.success())
}

/// SSH-agent auth is currently only wired up on Unix (Unix domain socket).
#[cfg(not(unix))]
async fn authenticate_agent(
    _handle: &mut Handle<Handler>,
    _username: &str,
) -> Result<bool, ConnectError> {
    Err(ConnectError::Other(anyhow!(
        "SSH-agent authentication isn't supported on this platform yet; use a key or password"
    )))
}

/// Tries each identity the SSH agent offers until one authenticates.
#[cfg(unix)]
async fn authenticate_agent(
    handle: &mut Handle<Handler>,
    username: &str,
) -> Result<bool, ConnectError> {
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|e| ConnectError::Other(anyhow!("could not reach the SSH agent: {e}")))?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| ConnectError::Other(anyhow!("could not list agent keys: {e}")))?;
    if identities.is_empty() {
        return Err(ConnectError::Other(anyhow!("the SSH agent has no keys loaded")));
    }

    let mut signer = AgentSigner(agent);
    for identity in identities {
        let public = identity.public_key().into_owned();
        let hash = if public.algorithm().is_rsa() { Some(HashAlg::Sha256) } else { None };
        let result = handle
            .authenticate_publickey_with(username, public, hash, &mut signer)
            .await
            .map_err(|e| ConnectError::Other(anyhow!("agent authentication failed: {e}")))?;
        if result.success() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Adapts an [`AgentClient`] to russh's [`Signer`] so the agent signs auth challenges.
#[cfg(unix)]
struct AgentSigner(AgentClient<tokio::net::UnixStream>);

/// Errors from agent signing. russh's [`Signer`] requires `From<SendError>`,
/// which [`russh::Error`] does not provide, so this wraps both.
#[cfg(unix)]
#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error(transparent)]
    Keys(#[from] russh::keys::Error),
}

#[cfg(unix)]
impl russh::Signer for AgentSigner {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        key: &russh::keys::agent::AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.0.sign_request(key, hash_alg, to_sign).await?)
    }
}

/// The RSA signature hash the server supports, or `None` for non-RSA keys.
async fn rsa_hash(
    handle: &Handle<Handler>,
    key: &PrivateKey,
) -> Result<Option<HashAlg>, ConnectError> {
    if key.algorithm().is_rsa() {
        Ok(handle.best_supported_rsa_hash().await.map_err(to_other)?.flatten())
    } else {
        Ok(None)
    }
}

/// Opens the shell channel and relays data in both directions.
async fn pump(
    handle: Handle<Handler>,
    params: ConnectParams,
    wake: &(impl Fn() + Send),
    out: &SyncSender<BackendEvent>,
    mut cmds: UnboundedReceiver<Cmd>,
    mut sftp_rx: UnboundedReceiver<SftpRequest>,
) -> anyhow::Result<()> {
    let channel = handle.channel_open_session().await?;
    let size = params.size;
    channel
        .request_pty(
            false,
            "xterm-256color",
            size.cols as u32,
            size.rows as u32,
            (size.cols as u32) * (size.cell_width as u32),
            (size.rows as u32) * (size.cell_height as u32),
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    // Opened lazily on the first SFTP request, then reused.
    let mut sftp_session: Option<StdArc<SftpSession>> = None;
    // Set to false once all SFTP handles are dropped, to stop polling that arm.
    let mut sftp_open = true;

    let mut channel = channel;
    loop {
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Data(bytes)) => channel.data(&bytes[..]).await?,
                Some(Cmd::Resize(size)) => {
                    channel
                        .window_change(
                            size.cols as u32,
                            size.rows as u32,
                            (size.cols as u32) * (size.cell_width as u32),
                            (size.rows as u32) * (size.cell_height as u32),
                        )
                        .await?;
                }
                // Backend dropped: close the channel and finish.
                None => {
                    let _ = channel.eof().await;
                    let _ = handle.disconnect(Disconnect::ByApplication, "", "").await;
                    return Ok(());
                }
            },
            request = sftp_rx.recv(), if sftp_open => match request {
                Some(request) => {
                    match ensure_sftp(&handle, &mut sftp_session).await {
                        Ok(session) => {
                            // Run the op concurrently so transfers don't block the shell.
                            tokio::spawn(run_sftp_op(session, request));
                        }
                        Err(e) => {
                            let _ = request.reply.send(Err(e));
                        }
                    }
                }
                // All SFTP handles dropped; stop selecting on this arm.
                None => sftp_open = false,
            },
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    // A full output channel means the terminal is gone; stop.
                    if out.send(BackendEvent::Output(data.to_vec())).is_err() {
                        return Ok(());
                    }
                    wake();
                }
                Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) | None => return Ok(()),
                _ => {}
            },
        }
    }
}

fn to_other(e: russh::Error) -> ConnectError {
    ConnectError::Other(anyhow!(e))
}

/// Opens the SFTP subsystem on first use and returns a clone of the session
/// (cheap; the session is `Arc`-backed internally).
async fn ensure_sftp(
    handle: &Handle<Handler>,
    slot: &mut Option<StdArc<SftpSession>>,
) -> Result<StdArc<SftpSession>, String> {
    if slot.is_none() {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("could not open an SFTP channel: {e}"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| format!("the server refused SFTP: {e}"))?;
        let session = SftpSession::new(channel.into_stream()).await.map_err(|e| {
            log::warn!("SFTP subsystem init failed: {e}");
            format!(
                "the server closed the SFTP channel during setup ({e}). Its SSH \
                 server may not have the SFTP subsystem enabled for this account."
            )
        })?;
        *slot = Some(StdArc::new(session));
    }
    Ok(StdArc::clone(slot.as_ref().expect("just set")))
}

/// Runs one SFTP operation and sends its result back to the caller.
async fn run_sftp_op(session: StdArc<SftpSession>, request: SftpRequest) {
    let result = execute_sftp(&session, request.op).await.map_err(|e| e.to_string());
    let _ = request.reply.send(result);
}

async fn execute_sftp(
    session: &SftpSession,
    op: SftpOp,
) -> Result<SftpReply, russh_sftp::client::error::Error> {
    Ok(match op {
        SftpOp::Canonicalize(path) => SftpReply::Path(session.canonicalize(path).await?),
        SftpOp::ListDir(path) => {
            let entries = session
                .read_dir(path)
                .await?
                .map(|entry| {
                    let md = entry.metadata();
                    FileEntry {
                        name: entry.file_name(),
                        is_dir: md.is_dir(),
                        is_symlink: md.is_symlink(),
                        size: md.size.unwrap_or(0),
                        mtime: md.mtime,
                    }
                })
                .collect();
            SftpReply::Entries(entries)
        }
        SftpOp::Download { remote, local } => {
            let mut source = session.open(remote).await?;
            let mut dest = tokio::fs::File::create(&local)
                .await
                .map_err(russh_sftp::client::error::Error::from)?;
            tokio::io::copy(&mut source, &mut dest)
                .await
                .map_err(russh_sftp::client::error::Error::from)?;
            SftpReply::Done
        }
        SftpOp::Upload { local, remote } => {
            let mut source = tokio::fs::File::open(&local)
                .await
                .map_err(russh_sftp::client::error::Error::from)?;
            let mut dest = session
                .open_with_flags(
                    remote,
                    OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                )
                .await?;
            tokio::io::copy(&mut source, &mut dest)
                .await
                .map_err(russh_sftp::client::error::Error::from)?;
            dest.shutdown().await.map_err(russh_sftp::client::error::Error::from)?;
            SftpReply::Done
        }
        SftpOp::Mkdir(path) => {
            session.create_dir(path).await?;
            SftpReply::Done
        }
        SftpOp::Remove { path, is_dir } => {
            if is_dir {
                session.remove_dir(path).await?;
            } else {
                session.remove_file(path).await?;
            }
            SftpReply::Done
        }
        SftpOp::Rename { from, to } => {
            session.rename(from, to).await?;
            SftpReply::Done
        }
    })
}

/// Algorithm preferences. With `legacy` set, weak-but-widely-compatible
/// algorithms are appended after the modern defaults, so a modern server still
/// negotiates strong ones while old gear (ProCurve, legacy IOS) can still connect.
fn preferred_algorithms(legacy: bool) -> russh::Preferred {
    use std::borrow::Cow;

    let mut preferred = russh::Preferred::DEFAULT;
    if !legacy {
        return preferred;
    }

    let mut kex = preferred.kex.into_owned();
    kex.extend_from_slice(&[
        russh::kex::DH_GEX_SHA256,
        russh::kex::DH_G14_SHA256,
        russh::kex::DH_GEX_SHA1,
        russh::kex::DH_G14_SHA1,
        russh::kex::DH_G1_SHA1,
    ]);

    let mut cipher = preferred.cipher.into_owned();
    cipher.extend_from_slice(&[
        russh::cipher::AES_256_CBC,
        russh::cipher::AES_192_CBC,
        russh::cipher::AES_128_CBC,
        russh::cipher::TRIPLE_DES_CBC,
    ]);

    let mut mac = preferred.mac.into_owned();
    mac.extend_from_slice(&[russh::mac::HMAC_SHA256, russh::mac::HMAC_SHA1]);

    // Old gear often presents only an ssh-rsa (already in the defaults) or an
    // ssh-dss host key; advertise DSA so host-key negotiation can succeed.
    let mut key = preferred.key.into_owned();
    key.push(russh::keys::Algorithm::Dsa);

    preferred.kex = Cow::Owned(dedup(kex));
    preferred.cipher = Cow::Owned(dedup(cipher));
    preferred.mac = Cow::Owned(dedup(mac));
    preferred.key = Cow::Owned(dedup(key));
    preferred
}

/// Removes duplicates while keeping first-seen order (preference order matters).
fn dedup<T: PartialEq + Clone>(items: Vec<T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::preferred_algorithms;

    #[test]
    fn legacy_adds_old_algorithms_without_losing_modern() {
        let modern = preferred_algorithms(false);
        assert!(!modern.kex.contains(&russh::kex::DH_G14_SHA1));
        assert!(!modern.cipher.contains(&russh::cipher::AES_256_CBC));
        assert!(!modern.mac.contains(&russh::mac::HMAC_SHA1));

        let legacy = preferred_algorithms(true);
        // Modern algorithms stay, ranked ahead of the legacy ones.
        assert!(legacy.kex.contains(&russh::kex::MLKEM768X25519_SHA256));
        assert!(legacy.kex.contains(&russh::kex::DH_G14_SHA1));
        assert!(legacy.kex.contains(&russh::kex::DH_G1_SHA1));
        assert!(legacy.cipher.contains(&russh::cipher::AES_256_CBC));
        assert!(legacy.cipher.contains(&russh::cipher::TRIPLE_DES_CBC));
        assert!(legacy.mac.contains(&russh::mac::HMAC_SHA1));
    }

    #[test]
    fn legacy_lists_have_no_duplicates() {
        let legacy = preferred_algorithms(true);
        let mut kex = legacy.kex.to_vec();
        let len = kex.len();
        kex.dedup();
        kex.sort_by_key(|n| n.as_ref().to_owned());
        kex.dedup();
        assert_eq!(kex.len(), len, "kex list has duplicates");
    }
}
