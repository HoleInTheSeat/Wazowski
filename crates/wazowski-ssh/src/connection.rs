use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use russh::client::{self, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::HashAlg;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, decode_secret_key};
use russh::{ChannelMsg, Disconnect};
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use wazowski_term::{Backend, BackendEvent, TermSize};

use crate::host_key::{self, Handler, HostKeyPolicy, UnknownHostKey, Verdict};

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
    thread: Option<thread::JoinHandle<()>>,
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
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let thread = thread::Builder::new()
        .name(format!("ssh-{}", params.host))
        .spawn(move || {
            let runtime = match Builder::new_multi_thread().worker_threads(1).enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(ConnectError::Other(e.into())));
                    return;
                }
            };
            runtime.block_on(session_task(params, wake, out_tx, cmd_rx, ready_tx));
        })
        .map_err(|e| ConnectError::Other(e.into()))?;

    // Wait for the task to report whether the handshake succeeded.
    match ready_rx.recv() {
        Ok(Ok(())) => Ok((SshBackend { cmds: Some(cmd_tx), thread: Some(thread) }, out_rx)),
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
    ready: std::sync::mpsc::Sender<Result<(), ConnectError>>,
) {
    match establish(&params).await {
        Ok(handle) => {
            // Tell the caller we are connected before entering the loop.
            if ready.send(Ok(())).is_err() {
                return;
            }
            if let Err(e) = pump(handle, params, &wake, &out, cmds).await {
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
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
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

    authenticate(&mut handle, &params.username, &params.auth).await?;
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

/// Tries each identity the SSH agent offers until one authenticates.
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
struct AgentSigner(AgentClient<tokio::net::UnixStream>);

/// Errors from agent signing. russh's [`Signer`] requires `From<SendError>`,
/// which [`russh::Error`] does not provide, so this wraps both.
#[derive(Debug, thiserror::Error)]
enum SignError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error(transparent)]
    Keys(#[from] russh::keys::Error),
}

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
