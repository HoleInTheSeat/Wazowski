//! Opening SSH connections off the UI thread.
//!
//! [`wazowski_ssh::connect`] blocks until the handshake finishes, so each
//! attempt runs on its own thread and reports back through a channel the app
//! polls every frame. Unknown-host and changed-key outcomes become prompts; on
//! acceptance the attempt is retried after recording the key.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;

use egui::Context;
use wazowski_ssh::{ConnectError, ConnectParams, SshBackend, UnknownHostKey, connect};
use wazowski_term::BackendEvent;

use crate::conn_log::{self, LogSink};

/// A connection attempt running on a worker thread.
pub struct PendingConnect {
    result: Receiver<Result<Connected, ConnectError>>,
    /// Captures the handshake log (including russh negotiation) for display.
    sink: LogSink,
}

/// A freshly established session, handed to the app to wrap in a terminal tab.
pub struct Connected {
    pub backend: SshBackend,
    pub output: Receiver<BackendEvent>,
}

/// What polling a pending connection yields.
pub enum Progress {
    /// Still connecting.
    Waiting,
    /// Connected; take the session.
    Ready(Connected),
    /// The server's key is unknown; ask the user before trusting it.
    PromptUnknownHost(UnknownHostKey),
    /// The server's key changed since last time; warn strongly.
    PromptChangedHost(UnknownHostKey),
    /// Failed for another reason.
    Failed(String),
}

impl PendingConnect {
    /// Spawns a worker thread that connects with `params` and repaints `ctx` on completion.
    pub fn spawn(params: ConnectParams, ctx: &Context) -> Self {
        // Register the log sink before the worker starts so no lines are missed.
        let sink = conn_log::register();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_params = params;
        let repaint = ctx.clone();
        thread::Builder::new()
            .name("wz-connect".into())
            .spawn(move || {
                let outcome = connect(worker_params, {
                    let repaint = repaint.clone();
                    move || repaint.request_repaint()
                })
                .map(|(backend, output)| Connected { backend, output });
                let _ = tx.send(outcome);
                repaint.request_repaint();
            })
            .expect("spawning a thread should not fail");
        Self { result: rx, sink }
    }

    /// Drains newly captured handshake log lines into `buf`.
    pub fn drain_log(&self, buf: &mut Vec<String>) {
        self.sink.drain_into(buf);
    }

    /// Checks whether the attempt has finished, without blocking.
    pub fn poll(&self) -> Progress {
        match self.result.try_recv() {
            Err(TryRecvError::Empty) => Progress::Waiting,
            Ok(Ok(connected)) => Progress::Ready(connected),
            Ok(Err(ConnectError::UnknownHost(info))) => Progress::PromptUnknownHost(info),
            Ok(Err(ConnectError::HostKeyChanged(info))) => Progress::PromptChangedHost(info),
            Ok(Err(e)) => Progress::Failed(format!("{e:#}")),
            // Worker vanished without sending: treat as failure.
            Err(TryRecvError::Disconnected) => {
                Progress::Failed("the connection attempt ended unexpectedly".into())
            }
        }
    }
}
