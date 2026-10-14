//! iperf3 server, driven by the system `iperf3` binary.

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::{Log, Ready, ServerConfig};

pub(crate) async fn serve(
    cfg: &ServerConfig,
    shutdown: oneshot::Receiver<()>,
    log: Log,
    ready: &Ready,
) -> Result<()> {
    let port = cfg.port.to_string();
    let mut command = Command::new("iperf3");
    command.arg("-s").arg("-p").arg(&port);
    // Bind to a specific interface unless serving all of them.
    if cfg.bind != IpAddr::from([0, 0, 0, 0]) {
        command.arg("-B").arg(cfg.bind.to_string());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = if e.kind() == std::io::ErrorKind::NotFound {
                crate::StartError::NotInstalled("iperf3".into())
            } else {
                crate::StartError::Other(e.to_string())
            };
            let _ = ready.send(Err(err));
            return Ok(());
        }
    };
    let _ = ready.send(Ok(format!("iperf3 :{port}")));
    log.line(format!("iperf3 server listening on {}:{port}", cfg.bind));

    // Stream the child's stdout and stderr into the log.
    if let Some(out) = child.stdout.take() {
        pipe_lines(out, log.clone());
    }
    if let Some(err) = child.stderr.take() {
        pipe_lines(err, log.clone());
    }

    tokio::select! {
        status = child.wait() => {
            let status = status.context("waiting for iperf3")?;
            if !status.success() {
                log.line(format!("iperf3 exited: {status}"));
            }
            Ok(())
        }
        _ = shutdown => {
            let _ = child.kill().await;
            Ok(())
        }
    }
}

/// Spawns a task that forwards each line from `reader` to the log.
fn pipe_lines<R>(reader: R, log: Log)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if !line.trim().is_empty() {
                log.line(line);
            }
        }
    });
}
