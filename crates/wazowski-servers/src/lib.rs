//! Quick servers: serve a folder over HTTP/TFTP/SFTP, or run an iperf3 server,
//! on a chosen interface and port. Each running server lives on a shared tokio
//! runtime and streams a live log back to the caller.

mod http;
mod iperf;
mod sftp;
mod tftp;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, Sender, channel};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;

/// The kind of quick server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKind {
    #[default]
    Http,
    Tftp,
    Sftp,
    Iperf,
}

impl ServerKind {
    pub fn label(self) -> &'static str {
        match self {
            ServerKind::Http => "HTTP",
            ServerKind::Tftp => "TFTP",
            ServerKind::Sftp => "SFTP",
            ServerKind::Iperf => "iperf3",
        }
    }

    /// Whether this server serves a folder (vs iperf, which doesn't).
    pub fn uses_root(self) -> bool {
        !matches!(self, ServerKind::Iperf)
    }

    pub fn default_port(self) -> u16 {
        match self {
            ServerKind::Http => 8080,
            ServerKind::Tftp => 69,
            ServerKind::Sftp => 2222,
            ServerKind::Iperf => 5201,
        }
    }
}

/// A persisted server definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub id: String,
    pub name: String,
    pub kind: ServerKind,
    /// Folder to serve (HTTP/TFTP/SFTP).
    #[serde(default)]
    pub root: PathBuf,
    /// Bind address, e.g. `0.0.0.0` (all interfaces) or `127.0.0.1`.
    pub bind: IpAddr,
    pub port: u16,
    /// Allow writes/uploads (TFTP/SFTP).
    #[serde(default)]
    pub writable: bool,
    /// SFTP username (empty = anonymous, any username accepted).
    #[serde(default)]
    pub username: String,
    /// SFTP password (empty = accept any).
    #[serde(default)]
    pub password: String,
}

/// A handle to a running server. Dropping or [`stop`](Self::stop)ping it shuts
/// the server down.
pub struct RunningServer {
    shutdown: Option<oneshot::Sender<()>>,
    log_rx: Receiver<String>,
    addr: String,
}

impl RunningServer {
    /// The address the server is listening on.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Drains newly logged lines into `buf`.
    pub fn drain_log(&self, buf: &mut Vec<String>) {
        while let Ok(line) = self.log_rx.try_recv() {
            buf.push(line);
        }
    }

    /// Stops the server (also happens on drop).
    pub fn stop(mut self) {
        self.shutdown.take();
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.take();
    }
}

/// The shared runtime that hosts all running servers.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("wz-servers")
            .build()
            .expect("failed to build the servers runtime")
    })
}

/// A logger a running server writes lines to.
#[derive(Clone)]
pub(crate) struct Log {
    tx: Sender<String>,
    wake: std::sync::Arc<dyn Fn() + Send + Sync>,
}

impl Log {
    pub(crate) fn line(&self, msg: impl Into<String>) {
        let _ = self.tx.send(msg.into());
        (self.wake)();
    }
}

/// Starts a server from its config. Blocks only briefly (until the socket is
/// bound), then serves in the background; `wake` is called when new log lines
/// arrive so the UI can repaint.
pub fn start(cfg: &ServerConfig, wake: impl Fn() + Send + Sync + 'static) -> Result<RunningServer> {
    let (log_tx, log_rx) = channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let log = Log { tx: log_tx, wake: std::sync::Arc::new(wake) };
    let cfg = cfg.clone();

    runtime().spawn(async move {
        let result = serve(&cfg, shutdown_rx, log.clone(), &ready_tx).await;
        match result {
            Ok(()) => log.line("Server stopped."),
            Err(e) => {
                // Report the error to the starter if we never got ready.
                let _ = ready_tx.send(Err(format!("{e:#}")));
                log.line(format!("Server error: {e:#}"));
            }
        }
    });

    // Wait for bind to succeed (or fail) before returning.
    match ready_rx.recv() {
        Ok(Ok(addr)) => Ok(RunningServer { shutdown: Some(shutdown_tx), log_rx, addr }),
        Ok(Err(e)) => Err(anyhow::anyhow!(e)),
        Err(_) => Err(anyhow::anyhow!("the server task exited before starting")),
    }
}

/// Lists usable bind addresses for the UI: all interfaces, localhost, and each
/// detected local IPv4.
pub fn bind_options() -> Vec<(String, IpAddr)> {
    let mut opts = vec![
        ("All interfaces (0.0.0.0)".to_string(), IpAddr::from([0, 0, 0, 0])),
        ("Localhost (127.0.0.1)".to_string(), IpAddr::from([127, 0, 0, 1])),
    ];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let ip = iface.ip();
            if ip.is_ipv4() && !ip.is_loopback() {
                opts.push((format!("{} ({})", iface.name, ip), ip));
            }
        }
    }
    opts
}

/// Reports a successfully bound address, or the failure, to the starter.
pub(crate) type Ready = std::sync::mpsc::Sender<std::result::Result<String, String>>;

async fn serve(
    cfg: &ServerConfig,
    shutdown: oneshot::Receiver<()>,
    log: Log,
    ready: &Ready,
) -> Result<()> {
    match cfg.kind {
        ServerKind::Http => http::serve(cfg, shutdown, log, ready).await,
        ServerKind::Tftp => tftp::serve(cfg, shutdown, log, ready).await,
        ServerKind::Sftp => sftp::serve(cfg, shutdown, log, ready).await,
        ServerKind::Iperf => iperf::serve(cfg, shutdown, log, ready).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn cfg(kind: ServerKind, root: PathBuf) -> ServerConfig {
        ServerConfig {
            id: "t".into(),
            name: "test".into(),
            kind,
            root,
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 0, // ephemeral
            writable: false,
            username: String::new(),
            password: String::new(),
        }
    }

    #[test]
    fn http_serves_a_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hi there").unwrap();

        let server = start(&cfg(ServerKind::Http, dir.path().to_path_buf()), || {}).unwrap();
        // addr looks like "http://127.0.0.1:PORT"
        let hostport = server.addr().trim_start_matches("http://").to_owned();

        let mut stream = TcpStream::connect(&hostport).unwrap();
        write!(stream, "GET /hello.txt HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response}");
        assert!(response.contains("hi there"), "body missing: {response}");
    }

    #[test]
    fn bind_options_include_defaults() {
        let opts = bind_options();
        assert!(opts.iter().any(|(_, ip)| *ip == IpAddr::from([0, 0, 0, 0])));
        assert!(opts.iter().any(|(_, ip)| *ip == IpAddr::from([127, 0, 0, 1])));
    }
}

#[cfg(test)]
mod sftp_tests {
    use super::*;
    use std::io::Write as _;
    use wazowski_ssh::{AuthMaterial, ConnectParams, HostKeyPolicy, connect};
    use wazowski_term::TermSize;

    #[test]
    #[ignore = "spawns an SFTP server and connects a real SSH client"]
    fn sftp_server_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), b"served file").unwrap();

        let mut cfg = ServerConfig {
            id: "sftp-test".into(),
            name: "sftp".into(),
            kind: ServerKind::Sftp,
            root: dir.path().to_path_buf(),
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 0,
            writable: true,
            username: "user".into(),
            password: "pw".into(),
        };
        let server = start(&cfg, || {}).unwrap();
        // addr is "sftp://127.0.0.1:PORT"
        let port: u16 = server.addr().rsplit(':').next().unwrap().parse().unwrap();
        cfg.port = port;

        let known = tempfile::NamedTempFile::new().unwrap();
        let (backend, _rx) = connect(
            ConnectParams {
                host: "127.0.0.1".into(),
                port,
                username: "user".into(),
                auth: AuthMaterial::Password("pw".into()),
                policy: HostKeyPolicy::AcceptNew,
                size: TermSize::default(),
                known_hosts: Some(known.path().to_path_buf()),
                legacy_algorithms: false,
            },
            || {},
        )
        .expect("connect to sftp server");
        let sftp = backend.sftp();

        // List the served folder and read the existing file back.
        let entries = sftp.list_dir("/").expect("list");
        assert!(entries.iter().any(|e| e.name == "readme.txt"), "listing: {entries:?}");

        let local = dir.path().join("downloaded.txt");
        sftp.download("/readme.txt", local.clone()).expect("download");
        assert_eq!(std::fs::read(&local).unwrap(), b"served file");

        // Upload a new file and confirm it lands in the served folder.
        let up = dir.path().join("upload.txt");
        std::fs::File::create(&up).unwrap().write_all(b"uploaded").unwrap();
        sftp.upload(up, "/newfile.txt").expect("upload");
        assert_eq!(std::fs::read(dir.path().join("newfile.txt")).unwrap(), b"uploaded");
    }
}
