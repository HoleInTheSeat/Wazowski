//! A logger that both prints to stderr (respecting `RUST_LOG`) and broadcasts
//! records to any registered sinks, so a connection tab can show a live,
//! copyable log of the SSH handshake — including russh's negotiation detail.
//!
//! russh and our own crates are forced to DEBUG so the key-exchange trace is
//! always captured for troubleshooting (e.g. old switches), even if `RUST_LOG`
//! would hide it from stderr. Capture work is skipped entirely when no sink is
//! registered, so there is no cost outside an active connection.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, OnceLock};

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Broadcast {
    env: env_logger::Logger,
    sinks: Mutex<Vec<(u64, Sender<String>)>>,
    sink_count: AtomicUsize,
}

static BROADCAST: OnceLock<Broadcast> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Installs the logger. Safe to call once at startup; ignores a second call.
pub fn init() {
    let env = env_logger::Builder::from_default_env().build();
    let stderr_level = env.filter();
    let broadcast = BROADCAST.get_or_init(|| Broadcast {
        env,
        sinks: Mutex::new(Vec::new()),
        sink_count: AtomicUsize::new(0),
    });
    // Capture russh/wazowski at DEBUG regardless of RUST_LOG, but never below
    // what the user asked stderr to show.
    let max = stderr_level.max(LevelFilter::Debug);
    if log::set_logger(broadcast).is_ok() {
        log::set_max_level(max);
    }
}

impl Log for Broadcast {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        // stderr, per RUST_LOG.
        if self.env.matches(record) {
            self.env.log(record);
        }
        // Broadcast to connection tabs, if any are listening.
        if self.sink_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        if !should_capture(record) {
            return;
        }
        let line = format!("[{}] {}", record.level(), record.args());
        let mut sinks = self.sinks.lock().expect("log sinks poisoned");
        sinks.retain(|(_, tx)| tx.send(line.clone()).is_ok());
        self.sink_count.store(sinks.len(), Ordering::Relaxed);
    }

    fn flush(&self) {
        self.env.flush();
    }
}

/// Whether a record is interesting enough to show in a connection log.
fn should_capture(record: &Record) -> bool {
    let target = record.target();
    target.starts_with("russh") || target.starts_with("wazowski") || record.level() <= Level::Info
}

/// A registered sink that receives log lines until dropped.
pub struct LogSink {
    id: u64,
    rx: Receiver<String>,
}

impl LogSink {
    /// Drains all buffered lines into `buf`.
    pub fn drain_into(&self, buf: &mut Vec<String>) {
        while let Ok(line) = self.rx.try_recv() {
            buf.push(line);
        }
    }
}

impl Drop for LogSink {
    fn drop(&mut self) {
        if let Some(b) = BROADCAST.get() {
            let mut sinks = b.sinks.lock().expect("log sinks poisoned");
            sinks.retain(|(id, _)| *id != self.id);
            b.sink_count.store(sinks.len(), Ordering::Relaxed);
        }
    }
}

/// Registers a new sink to capture subsequent log lines.
pub fn register() -> LogSink {
    let (tx, rx) = channel();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Some(b) = BROADCAST.get() {
        let mut sinks = b.sinks.lock().expect("log sinks poisoned");
        sinks.push((id, tx));
        b.sink_count.store(sinks.len(), Ordering::Relaxed);
    }
    LogSink { id, rx }
}
