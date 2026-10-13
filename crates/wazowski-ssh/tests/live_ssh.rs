//! End-to-end test against a throwaway `sshd`.
//!
//! Ignored by default because it needs the OpenSSH `sshd` binary and binds a
//! local port. Run it with:
//!
//! ```text
//! cargo test -p wazowski-ssh --test live_ssh -- --ignored --nocapture
//! ```

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use wazowski_term::{BackendEvent, TermSize, Terminal};
use wazowski_ssh::{AuthMaterial, ConnectParams, HostKeyPolicy, connect};

/// A disposable sshd and the key material a client needs to log into it.
struct TestServer {
    child: Child,
    port: u16,
    client_key_pem: String,
    _dir: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn keygen(path: &std::path::Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen must be installed");
    assert!(status.success(), "ssh-keygen failed");
}

fn start_server() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    // Host key and a client key pair.
    let host_key = d.join("host_ed25519");
    keygen(&host_key);
    let client_key = d.join("client_ed25519");
    keygen(&client_key);
    let client_key_pem = fs::read_to_string(&client_key).unwrap();

    // Authorize the client key.
    let authorized = d.join("authorized_keys");
    fs::copy(client_key.with_extension("pub").as_path(), &authorized).unwrap();
    // sshd insists authorized_keys is not group/other writable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&authorized, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let port = free_port();
    let config = d.join("sshd_config");
    let mut f = fs::File::create(&config).unwrap();
    writeln!(
        f,
        "Port {port}\n\
         ListenAddress 127.0.0.1\n\
         HostKey {host}\n\
         PidFile {pid}\n\
         AuthorizedKeysFile {auth}\n\
         UsePAM no\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\n\
         StrictModes no\n\
         Subsystem sftp internal-sftp\n",
        host = host_key.display(),
        pid = d.join("sshd.pid").display(),
        auth = authorized.display(),
    )
    .unwrap();

    let sshd = ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("sshd binary not found");

    // -D keeps it in the foreground; -e logs to stderr.
    let child = Command::new(sshd)
        .arg("-D")
        .arg("-f")
        .arg(&config)
        .spawn()
        .expect("could not start sshd");

    // Wait for the port to accept connections.
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "sshd did not start listening");
        std::thread::sleep(Duration::from_millis(50));
    }

    TestServer { child, port, client_key_pem, _dir: dir }
}

/// Drives a terminal until `needle` appears on screen or the deadline passes.
fn wait_for(term: &mut Terminal, ctx: &egui::Context, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !term.screen_text().contains(needle) {
        assert!(
            Instant::now() < deadline,
            "never saw {needle:?}; screen was:\n{}",
            term.screen_text()
        );
        std::thread::sleep(Duration::from_millis(50));
        term.process(ctx);
    }
}

#[test]
#[ignore = "spawns a local sshd"]
fn key_auth_runs_a_remote_shell() {
    let server = start_server();
    let known_hosts = tempfile::NamedTempFile::new().unwrap();

    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: whoami(),
        auth: AuthMaterial::Key { pem: server.client_key_pem.clone(), passphrase: None },
        policy: HostKeyPolicy::AcceptNew,
        size: TermSize::default(),
        known_hosts: Some(known_hosts.path().to_path_buf()),
    };

    let (backend, rx): (_, Receiver<BackendEvent>) = connect(params, || {}).expect("connect failed");
    let mut term = Terminal::new(Box::new(backend), rx, TermSize::default());
    let ctx = egui::Context::default();

    // A unique marker proves our keystrokes reached the remote shell and came back.
    term.write(b"echo wz-$((21*2))-ok\n");
    wait_for(&mut term, &ctx, "wz-42-ok");

    // known_hosts should have learned the server key under AcceptNew.
    let learned = fs::read_to_string(known_hosts.path()).unwrap();
    assert!(learned.contains("ssh-ed25519"), "host key was not recorded: {learned:?}");
}

#[test]
#[ignore = "spawns a local sshd"]
fn wrong_key_is_rejected() {
    let server = start_server();
    let known_hosts = tempfile::NamedTempFile::new().unwrap();

    // A different, unauthorized key.
    let dir = tempfile::tempdir().unwrap();
    let other = dir.path().join("other");
    keygen(&other);

    let params = ConnectParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: whoami(),
        auth: AuthMaterial::Key { pem: fs::read_to_string(&other).unwrap(), passphrase: None },
        policy: HostKeyPolicy::AcceptNew,
        size: TermSize::default(),
        known_hosts: Some(known_hosts.path().to_path_buf()),
    };

    match connect(params, || {}).map(|_| ()) {
        Err(wazowski_ssh::ConnectError::AuthFailed) => {}
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

fn whoami() -> String {
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_else(|_| "root".into())
}
