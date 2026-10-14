//! SFTP server (serves a directory over SSH). Implemented in a later step.

use anyhow::{Result, bail};
use tokio::sync::oneshot;

use crate::{Log, Ready, ServerConfig};

pub(crate) async fn serve(
    _cfg: &ServerConfig,
    _shutdown: oneshot::Receiver<()>,
    _log: Log,
    ready: &Ready,
) -> Result<()> {
    let _ = ready.send(Err("the SFTP server isn't implemented yet".into()));
    bail!("SFTP server not implemented");
}
