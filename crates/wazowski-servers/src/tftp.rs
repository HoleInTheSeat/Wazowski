//! TFTP server (serves a directory; optionally writable for uploads).

use anyhow::{Context, Result};
use async_tftp::server::TftpServerBuilder;
use std::net::SocketAddr;
use tokio::sync::oneshot;

use crate::{Log, Ready, ServerConfig};

pub(crate) async fn serve(
    cfg: &ServerConfig,
    shutdown: oneshot::Receiver<()>,
    log: Log,
    ready: &Ready,
) -> Result<()> {
    let addr = SocketAddr::new(cfg.bind, cfg.port);
    let builder = if cfg.writable {
        TftpServerBuilder::with_dir_rw(&cfg.root)
    } else {
        TftpServerBuilder::with_dir_ro(&cfg.root)
    }
    .context("could not open the TFTP directory")?;

    let tftpd = match builder.bind(addr).build().await {
        Ok(s) => s,
        Err(e) => {
            // async-tftp wraps the IO error; privileged ports surface as "permission".
            let msg = e.to_string();
            let err = if cfg.port < 1024 && msg.to_lowercase().contains("permission") {
                crate::StartError::PrivilegedPort(cfg.port)
            } else {
                crate::StartError::Other(format!("could not start TFTP on {addr}: {e}"))
            };
            let _ = ready.send(Err(err));
            return Ok(());
        }
    };
    let local = tftpd.listen_addr().context("listen_addr")?;
    let _ = ready.send(Ok(format!("tftp://{local}")));
    log.line(format!(
        "TFTP serving {} on {local} ({})",
        cfg.root.display(),
        if cfg.writable { "read/write" } else { "read-only" }
    ));

    // `serve` runs until cancelled; dropping the future on shutdown stops it.
    tokio::select! {
        result = tftpd.serve() => result.context("tftp server error"),
        _ = shutdown => Ok(()),
    }
}
