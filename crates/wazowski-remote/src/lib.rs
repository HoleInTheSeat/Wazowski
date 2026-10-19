//! In-window remote-desktop backends for Wazowski.
//!
//! Each backend runs its protocol client on a dedicated thread with its own
//! Tokio runtime, and bridges to the (synchronous) egui UI through three cheap
//! channels on a [`RemoteHandle`]:
//!
//! * a shared [`FrameBuf`] the UI blits into a texture when `seq` changes,
//! * a stream of [`RemoteEvent`]s (resize, error, disconnect), and
//! * an input sink the UI pushes [`RemoteInput`] into (mouse/keyboard).
//!
//! The UI never touches Tokio or the protocol crates directly. Today VNC
//! (RFB, via `vnc-rs`) is implemented; RDP (via `ironrdp`) plugs in the same way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

mod rdp;
mod vnc;

/// The current remote framebuffer, in tightly-packed RGBA (egui's pixel order).
///
/// `seq` is bumped on every change so the UI uploads a new texture only when
/// something actually changed.
#[derive(Default)]
pub struct FrameBuf {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
    pub seq: u64,
}

/// An event from a backend to the UI.
#[derive(Debug, Clone)]
pub enum RemoteEvent {
    /// The remote desktop is now `w`×`h` pixels.
    Resized(u16, u16),
    /// A fatal error; the session has stopped.
    Error(String),
    /// The connection closed cleanly.
    Disconnected,
}

/// An input event from the UI to a backend. Coordinates are in remote pixels.
#[derive(Debug, Clone)]
pub enum RemoteInput {
    /// Pointer at `(x, y)` with an RFB-style button mask (bit0 left, bit1 middle,
    /// bit2 right, bit3 wheel-up, bit4 wheel-down).
    Pointer { x: u16, y: u16, buttons: u8 },
    /// A key transition, by X11 keysym.
    Key { keysym: u32, down: bool },
}

/// Per-protocol connection options.
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    /// VNC: don't forward input (observe only).
    pub view_only: bool,
    /// VNC: ask the server to keep other clients connected.
    pub shared: bool,
    /// VNC: preferred encoding set (bandwidth vs. fidelity).
    pub quality: VncQuality,
}

impl Default for RemoteOptions {
    fn default() -> Self {
        Self { view_only: false, shared: true, quality: VncQuality::Auto }
    }
}

/// VNC encoding preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncQuality {
    /// Balanced: ZRLE + CopyRect + Raw.
    Auto,
    /// Favor fidelity: Raw-heavy (more bandwidth).
    High,
    /// Favor bandwidth: ZRLE-first.
    Low,
}

/// A live remote-desktop session. Dropping it stops the backend thread.
pub struct RemoteHandle {
    frame: Arc<Mutex<FrameBuf>>,
    events: std::sync::mpsc::Receiver<RemoteEvent>,
    input_tx: tokio::sync::mpsc::UnboundedSender<RemoteInput>,
    shutdown: Arc<AtomicBool>,
    _join: std::thread::JoinHandle<()>,
}

impl RemoteHandle {
    /// Queues an input event for the backend (ignored once disconnected).
    pub fn send_input(&self, input: RemoteInput) {
        let _ = self.input_tx.send(input);
    }

    /// Drains any backend events emitted since the last call.
    pub fn poll_events(&self) -> Vec<RemoteEvent> {
        self.events.try_iter().collect()
    }

    /// Reads the current framebuffer under lock.
    pub fn with_frame<R>(&self, f: impl FnOnce(&FrameBuf) -> R) -> R {
        let guard = self.frame.lock().expect("frame mutex poisoned");
        f(&guard)
    }
}

impl Drop for RemoteHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// Connects to a VNC server, returning a handle whose backend thread drives the
/// session. `password` is used only if the server requests authentication.
pub fn connect_vnc(
    host: &str,
    port: u16,
    password: Option<String>,
    options: RemoteOptions,
) -> RemoteHandle {
    let frame = Arc::new(Mutex::new(FrameBuf::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();

    let host = host.to_owned();
    let frame_bg = Arc::clone(&frame);
    let shutdown_bg = Arc::clone(&shutdown);
    let join = std::thread::Builder::new()
        .name("wazowski-vnc".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ev_tx.send(RemoteEvent::Error(format!("runtime: {e}")));
                    return;
                }
            };
            rt.block_on(vnc::run(host, port, password, options, frame_bg, ev_tx, in_rx, shutdown_bg));
        })
        .expect("spawn vnc thread");

    RemoteHandle { frame, events: ev_rx, input_tx: in_tx, shutdown, _join: join }
}

/// Connects to an RDP server (native, in-window), returning a session handle.
#[allow(clippy::too_many_arguments)]
pub fn connect_rdp(
    host: &str,
    port: u16,
    username: &str,
    password: Option<String>,
    domain: &str,
    width: u16,
    height: u16,
    view_only: bool,
) -> RemoteHandle {
    let frame = Arc::new(Mutex::new(FrameBuf::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();

    let params = rdp::RdpParams {
        host: host.to_owned(),
        port,
        username: username.to_owned(),
        password: password.unwrap_or_default(),
        domain: domain.to_owned(),
        width,
        height,
        view_only,
    };
    let frame_bg = Arc::clone(&frame);
    let shutdown_bg = Arc::clone(&shutdown);
    let join = std::thread::Builder::new()
        .name("wazowski-rdp".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ev_tx.send(RemoteEvent::Error(format!("runtime: {e}")));
                    return;
                }
            };
            rt.block_on(rdp::run(params, frame_bg, ev_tx, in_rx, shutdown_bg));
        })
        .expect("spawn rdp thread");

    RemoteHandle { frame, events: ev_rx, input_tx: in_tx, shutdown, _join: join }
}
