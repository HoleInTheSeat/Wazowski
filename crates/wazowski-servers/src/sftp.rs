//! SFTP server: serves a folder over SSH (password auth), confined to that folder.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::keys::ssh_key::{Algorithm, PrivateKey};
use russh::server::{Auth, Config, Handler as SshHandler, Msg, Server as SshServer, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::{Log, Ready, ServerConfig};

pub(crate) async fn serve(
    cfg: &ServerConfig,
    shutdown: oneshot::Receiver<()>,
    log: Log,
    ready: &Ready,
) -> Result<()> {
    let key = host_key(&cfg.id).context("preparing the SFTP host key")?;
    let config = Arc::new(Config {
        methods: {
            let mut m = russh::MethodSet::empty();
            m.push(russh::MethodKind::Password);
            m
        },
        keys: vec![key],
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        ..Default::default()
    });

    let addr = SocketAddr::new(cfg.bind, cfg.port);
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            let _ = ready.send(Err(format!("could not bind {addr}: {e}")));
            return Ok(());
        }
    };
    let local = listener.local_addr().context("local_addr")?;
    let _ = ready.send(Ok(format!("sftp://{local}")));
    log.line(format!(
        "SFTP serving {} on {local} ({})",
        cfg.root.display(),
        if cfg.writable { "read/write" } else { "read-only" }
    ));

    let mut server = SftpServer {
        root: cfg.root.clone(),
        writable: cfg.writable,
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        log: log.clone(),
    };

    tokio::select! {
        result = server.run_on_socket(config, &listener) => {
            result.context("sftp server error")
        }
        _ = shutdown => Ok(()),
    }
}

/// Loads (or generates and persists) a per-server Ed25519 host key.
fn host_key(id: &str) -> Result<PrivateKey> {
    let dir = directories::ProjectDirs::from("org", "wazowski", "wazowski")
        .context("no data dir")?
        .data_dir()
        .join("server-keys");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("{id}.key"));
    if let Ok(pem) = std::fs::read_to_string(&path)
        && let Ok(key) = PrivateKey::from_openssh(&pem)
    {
        return Ok(key);
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("key generation failed: {e}"))?;
    if let Ok(pem) = key.to_openssh(russh::keys::ssh_key::LineEnding::LF) {
        let _ = std::fs::write(&path, pem.as_bytes());
    }
    Ok(key)
}

#[derive(Clone)]
struct SftpServer {
    root: PathBuf,
    writable: bool,
    username: String,
    password: String,
    log: Log,
}

impl SshServer for SftpServer {
    type Handler = SshConn;

    fn new_client(&mut self, _addr: Option<SocketAddr>) -> SshConn {
        SshConn {
            root: self.root.clone(),
            writable: self.writable,
            username: self.username.clone(),
            password: self.password.clone(),
            log: self.log.clone(),
            channels: HashMap::new(),
        }
    }
}

struct SshConn {
    root: PathBuf,
    writable: bool,
    username: String,
    password: String,
    log: Log,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl SshHandler for SshConn {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let user_ok = self.username.is_empty() || self.username == user;
        let pass_ok = self.password.is_empty() || self.password == password;
        if user_ok && pass_ok {
            self.log.line(format!("SFTP: {user} connected"));
            Ok(Auth::Accept)
        } else {
            self.log.line(format!("SFTP: rejected login for {user}"));
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp"
            && let Some(channel) = self.channels.remove(&channel_id)
        {
            session.channel_success(channel_id)?;
            let handler = SftpFs::new(self.root.clone(), self.writable, self.log.clone());
            russh_sftp::server::run(channel.into_stream(), handler).await;
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

/// Per-connection SFTP filesystem handler, confined to `root`.
struct SftpFs {
    root: PathBuf,
    writable: bool,
    log: Log,
    files: HashMap<String, std::fs::File>,
    /// Open directory handles: handle -> whether its listing was already sent.
    dirs: HashMap<String, bool>,
    /// Resolved real path for each open directory handle.
    dir_paths: HashMap<String, PathBuf>,
    next: u64,
}

impl SftpFs {
    fn new(root: PathBuf, writable: bool, log: Log) -> Self {
        Self {
            root,
            writable,
            log,
            files: HashMap::new(),
            dirs: HashMap::new(),
            dir_paths: HashMap::new(),
            next: 0,
        }
    }

    fn new_handle(&mut self, prefix: char) -> String {
        self.next += 1;
        format!("{prefix}{}", self.next)
    }

    /// Maps a client path to a real path within `root`, rejecting traversal.
    fn resolve(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let mut full = self.root.clone();
        for comp in Path::new(path.trim_start_matches('/')).components() {
            match comp {
                Component::Normal(c) => full.push(c),
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
                // No escaping the served folder.
                Component::ParentDir => return Err(StatusCode::PermissionDenied),
            }
        }
        Ok(full)
    }

    /// The virtual (client-facing) absolute path for a client input.
    fn virtual_path(path: &str) -> String {
        let mut out: Vec<&str> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                p => out.push(p),
            }
        }
        format!("/{}", out.join("/"))
    }

    fn require_writable(&self) -> Result<(), StatusCode> {
        if self.writable { Ok(()) } else { Err(StatusCode::PermissionDenied) }
    }
}

/// Maps an IO error to the closest SFTP status code.
fn io_status(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok_status(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en".into() }
}

impl russh_sftp::server::Handler for SftpFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, StatusCode> {
        let vpath = Self::virtual_path(&path);
        // Report attrs if the target exists; a bare path is fine otherwise.
        let attrs = self
            .resolve(&vpath)
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| FileAttributes::from(&m))
            .unwrap_or_default();
        Ok(Name { id, files: vec![File::new(vpath, attrs)] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        let real = self.resolve(&path)?;
        let md = std::fs::metadata(&real).map_err(|e| io_status(&e))?;
        Ok(Attrs { id, attrs: FileAttributes::from(&md) })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, StatusCode> {
        let real = self.resolve(&path)?;
        let md = std::fs::symlink_metadata(&real).map_err(|e| io_status(&e))?;
        Ok(Attrs { id, attrs: FileAttributes::from(&md) })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusCode> {
        let file = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let md = file.metadata().map_err(|e| io_status(&e))?;
        Ok(Attrs { id, attrs: FileAttributes::from(&md) })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, StatusCode> {
        let real = self.resolve(&path)?;
        if !real.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }
        let handle = self.new_handle('d');
        // Store the resolved path encoded in the handle via a side map.
        self.dirs.insert(handle.clone(), false);
        // Remember the path by reusing files map? Use a dedicated map keyed by handle.
        self.open_dir_paths_insert(&handle, real);
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, StatusCode> {
        // Directories are listed once; a second call signals EOF.
        let sent = self.dirs.get(&handle).copied().ok_or(StatusCode::Failure)?;
        if sent {
            return Err(StatusCode::Eof);
        }
        let path = self.open_dir_paths_get(&handle).ok_or(StatusCode::Failure)?;
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&path).map_err(|e| io_status(&e))? {
            let entry = entry.map_err(|e| io_status(&e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let attrs =
                entry.metadata().map(|m| FileAttributes::from(&m)).unwrap_or_default();
            files.push(File::new(name, attrs));
        }
        self.dirs.insert(handle, true);
        Ok(Name { id, files })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        let real = self.resolve(&filename)?;
        let mut opts = std::fs::OpenOptions::new();
        let wants_write = pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::CREATE);
        if wants_write {
            self.require_writable()?;
        }
        opts.read(pflags.contains(OpenFlags::READ));
        opts.write(pflags.contains(OpenFlags::WRITE));
        opts.append(pflags.contains(OpenFlags::APPEND));
        opts.create(pflags.contains(OpenFlags::CREATE));
        opts.truncate(pflags.contains(OpenFlags::TRUNCATE));
        if !pflags.contains(OpenFlags::READ) && !wants_write {
            opts.read(true);
        }
        let file = opts.open(&real).map_err(|e| io_status(&e))?;
        self.log.line(format!("SFTP {} {filename}", if wants_write { "put" } else { "get" }));
        let handle = self.new_handle('f');
        self.files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, StatusCode> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(|e| io_status(&e))?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).map_err(|e| io_status(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        self.require_writable()?;
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(SeekFrom::Start(offset)).map_err(|e| io_status(&e))?;
        file.write_all(&data).map_err(|e| io_status(&e))?;
        Ok(ok_status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, StatusCode> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        self.open_dir_paths_remove(&handle);
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusCode> {
        self.require_writable()?;
        std::fs::create_dir(self.resolve(&path)?).map_err(|e| io_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, StatusCode> {
        self.require_writable()?;
        std::fs::remove_dir(self.resolve(&path)?).map_err(|e| io_status(&e))?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, StatusCode> {
        self.require_writable()?;
        std::fs::remove_file(self.resolve(&filename)?).map_err(|e| io_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, StatusCode> {
        self.require_writable()?;
        std::fs::rename(self.resolve(&oldpath)?, self.resolve(&newpath)?)
            .map_err(|e| io_status(&e))?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusCode> {
        // Accept but ignore attribute changes (quick server).
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, StatusCode> {
        Ok(ok_status(id))
    }
}

// Side table of open-directory real paths, kept outside the trait's handle map.
impl SftpFs {
    fn open_dir_paths_insert(&mut self, handle: &str, path: PathBuf) {
        self.dir_paths.insert(handle.to_owned(), path);
    }
    fn open_dir_paths_get(&self, handle: &str) -> Option<PathBuf> {
        self.dir_paths.get(handle).cloned()
    }
    fn open_dir_paths_remove(&mut self, handle: &str) {
        self.dir_paths.remove(handle);
    }
}
