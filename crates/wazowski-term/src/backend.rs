use std::io;

/// Size of the terminal grid, plus the cell size in pixels (some programs ask for it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TermSize {
    pub cols: u16,
    pub rows: u16,
    pub cell_width: u16,
    pub cell_height: u16,
}

impl Default for TermSize {
    fn default() -> Self {
        Self { cols: 80, rows: 24, cell_width: 8, cell_height: 16 }
    }
}

/// Something a backend reports to its terminal.
#[derive(Debug)]
pub enum BackendEvent {
    /// Bytes for the terminal to display.
    Output(Vec<u8>),
    /// The process or connection behind the terminal has ended.
    Exited,
}

/// The byte stream a terminal talks to: a local PTY, an SSH channel, a serial port, ...
///
/// Output flows the other way, through the `Receiver<BackendEvent>` handed to
/// [`crate::Terminal::new`] alongside the backend.
pub trait Backend: Send {
    fn write(&mut self, data: &[u8]) -> io::Result<()>;
    fn resize(&mut self, size: TermSize) -> io::Result<()>;
}
