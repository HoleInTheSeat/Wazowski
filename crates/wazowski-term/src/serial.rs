//! Serial port as a terminal backend.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use serialport::SerialPort;

use crate::backend::{Backend, BackendEvent, TermSize};

/// Parity options for a serial connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialParity {
    None,
    Odd,
    Even,
}

/// Flow-control options for a serial connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialFlow {
    None,
    Software,
    Hardware,
}

/// How to open a serial port.
#[derive(Clone, Debug)]
pub struct SerialConfig {
    pub path: String,
    pub baud: u32,
    /// Data bits, 5–8.
    pub data_bits: u8,
    pub parity: SerialParity,
    /// Stop bits, 1 or 2.
    pub stop_bits: u8,
    pub flow: SerialFlow,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            baud: 115200,
            data_bits: 8,
            parity: SerialParity::None,
            stop_bits: 1,
            flow: SerialFlow::None,
        }
    }
}

/// Common baud rates, for a UI dropdown.
pub const COMMON_BAUDS: [u32; 9] =
    [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1500000];

/// Names of serial ports currently available on the system.
pub fn available_ports() -> Vec<String> {
    serialport::available_ports()
        .map(|ports| ports.into_iter().map(|p| p.port_name).collect())
        .unwrap_or_default()
}

/// An open serial port, usable as a terminal backend.
pub struct SerialBackend {
    writer: Box<dyn SerialPort>,
    running: Arc<AtomicBool>,
    reader: Option<thread::JoinHandle<()>>,
}

impl SerialBackend {
    /// Opens the serial port and starts a reader thread. `wake` is called when
    /// bytes arrive so the UI can repaint.
    pub fn open(
        config: &SerialConfig,
        wake: impl Fn() + Send + 'static,
    ) -> anyhow::Result<(Self, Receiver<BackendEvent>)> {
        let data_bits = match config.data_bits {
            5 => serialport::DataBits::Five,
            6 => serialport::DataBits::Six,
            7 => serialport::DataBits::Seven,
            _ => serialport::DataBits::Eight,
        };
        let parity = match config.parity {
            SerialParity::None => serialport::Parity::None,
            SerialParity::Odd => serialport::Parity::Odd,
            SerialParity::Even => serialport::Parity::Even,
        };
        let stop_bits =
            if config.stop_bits == 2 { serialport::StopBits::Two } else { serialport::StopBits::One };
        let flow = match config.flow {
            SerialFlow::None => serialport::FlowControl::None,
            SerialFlow::Software => serialport::FlowControl::Software,
            SerialFlow::Hardware => serialport::FlowControl::Hardware,
        };

        let writer = serialport::new(&config.path, config.baud)
            .data_bits(data_bits)
            .parity(parity)
            .stop_bits(stop_bits)
            .flow_control(flow)
            .timeout(Duration::from_millis(50))
            .open()?;
        let mut reader = writer.try_clone()?;

        let (tx, rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let reader_running = running.clone();
        let handle = thread::Builder::new().name("serial-reader".into()).spawn(move || {
            let mut buf = vec![0u8; 8 * 1024];
            while reader_running.load(Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        if tx.send(BackendEvent::Output(buf[..n].to_vec())).is_err() {
                            return;
                        }
                        wake();
                    }
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            let _ = tx.send(BackendEvent::Exited);
            wake();
        })?;

        Ok((Self { writer, running, reader: Some(handle) }, rx))
    }
}

impl Backend for SerialBackend {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()
    }

    fn resize(&mut self, _size: TermSize) -> io::Result<()> {
        Ok(()) // serial has no window size
    }

    fn set_baud(&mut self, baud: u32) -> io::Result<bool> {
        self.writer.set_baud_rate(baud).map_err(io::Error::other)?;
        Ok(true)
    }
}

impl Drop for SerialBackend {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}
