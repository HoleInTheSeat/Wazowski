use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, TermMode};
use alacritty_terminal::vte::ansi::Processor;

use crate::backend::{Backend, BackendEvent, TermSize};
use crate::colors::{Palette, to_rgb};

const DEFAULT_TITLE: &str = "Terminal";

/// One terminal session: emulator state plus the backend it is connected to.
pub struct Terminal {
    id: u64,
    pub(crate) term: Term<EventProxy>,
    parser: Processor,
    backend: Box<dyn Backend>,
    output: Receiver<BackendEvent>,
    term_events: Receiver<Event>,
    pub(crate) palette: Palette,
    size: TermSize,
    title: String,
    exited: bool,
    /// Fractional lines of mouse-wheel scrolling not yet applied.
    pub(crate) scroll_remainder: f32,
    /// Set when we asked egui for the clipboard, so the next paste event is a real paste.
    pub(crate) paste_requested: bool,
    /// User input recorded since the last drain, for multi-exec broadcast.
    broadcast_buf: Vec<u8>,
    /// When set, this terminal is skipped while multi-exec broadcast is on.
    exclude_broadcast: bool,
    /// Working directory reported by the shell via OSC 7, if any.
    cwd: Option<String>,
    /// Rolling tail of recent output, scanned for OSC 7 sequences.
    osc_buf: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct EventProxy(Sender<Event>);

impl EventListener for EventProxy {
    fn send_event(&self, event: Event) {
        let _ = self.0.send(event);
    }
}

struct Dims(TermSize);

impl Dimensions for Dims {
    fn total_lines(&self) -> usize {
        self.screen_lines()
    }

    fn screen_lines(&self) -> usize {
        self.0.rows as usize
    }

    fn columns(&self) -> usize {
        self.0.cols as usize
    }
}

impl Terminal {
    pub fn new(backend: Box<dyn Backend>, output: Receiver<BackendEvent>, size: TermSize) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let (tx, term_events) = mpsc::channel();
        let config = Config::default();
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            term: Term::new(config, &Dims(size), EventProxy(tx)),
            parser: Processor::new(),
            backend,
            output,
            term_events,
            palette: Palette::default(),
            size,
            title: DEFAULT_TITLE.to_owned(),
            exited: false,
            scroll_remainder: 0.0,
            broadcast_buf: Vec::new(),
            exclude_broadcast: false,
            cwd: None,
            osc_buf: Vec::new(),
            paste_requested: false,
        }
    }

    /// The working directory last reported by the shell via OSC 7, if any.
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Whether this terminal is currently excluded from multi-exec broadcast.
    pub fn broadcast_excluded(&self) -> bool {
        self.exclude_broadcast
    }

    pub fn set_broadcast_excluded(&mut self, excluded: bool) {
        self.exclude_broadcast = excluded;
    }

    /// Window title set by the running program, e.g. `user@host:~`.
    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn has_exited(&self) -> bool {
        self.exited
    }

    pub fn size(&self) -> TermSize {
        self.size
    }

    /// Feeds pending backend output into the emulator. Called each frame by [`crate::TerminalView`].
    pub fn process(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.output.try_recv() {
            match event {
                BackendEvent::Output(bytes) => {
                    self.scan_cwd(&bytes);
                    self.parser.advance(&mut self.term, &bytes);
                }
                BackendEvent::Exited => self.exited = true,
            }
        }

        let events: Vec<Event> = self.term_events.try_iter().collect();
        for event in events {
            match event {
                Event::PtyWrite(text) => self.write(text.as_bytes()),
                Event::Title(title) => self.title = title,
                Event::ResetTitle => self.title = DEFAULT_TITLE.to_owned(),
                Event::ClipboardStore(_, text) => ctx.copy_text(text),
                Event::ColorRequest(index, format) => {
                    let color = self.palette.indexed(index, self.term.colors());
                    self.write(format(to_rgb(color)).as_bytes());
                }
                Event::TextAreaSizeRequest(format) => {
                    let s = self.size;
                    let reply = format(WindowSize {
                        num_lines: s.rows,
                        num_cols: s.cols,
                        cell_width: s.cell_width,
                        cell_height: s.cell_height,
                    });
                    self.write(reply.as_bytes());
                }
                Event::ChildExit(_) | Event::Exit => self.exited = true,
                // Reading the clipboard from the remote side (OSC 52 query) is
                // deliberately not supported: it would let any program read it.
                _ => {}
            }
        }
    }

    /// Changes the serial baud rate on the fly. Returns whether this terminal's
    /// backend is a serial port (and the change applied).
    pub fn set_baud(&mut self, baud: u32) -> bool {
        match self.backend.set_baud(baud) {
            Ok(applied) => applied,
            Err(e) => {
                log::warn!("could not change baud rate: {e}");
                false
            }
        }
    }

    /// Scans recent output for OSC 7 (`ESC ] 7 ; file://host/path ST|BEL`) and
    /// updates the tracked working directory. Keeps a bounded rolling buffer so a
    /// sequence split across output chunks is still caught.
    fn scan_cwd(&mut self, bytes: &[u8]) {
        const MAX: usize = 4096;
        self.osc_buf.extend_from_slice(bytes);
        if self.osc_buf.len() > MAX {
            let cut = self.osc_buf.len() - MAX;
            self.osc_buf.drain(..cut);
        }
        let buf = self.osc_buf.clone();
        let mut from = 0;
        let mut found = None;
        let mut consumed = 0;
        while let Some(rel) = find(&buf[from..], b"\x1b]7;") {
            let start = from + rel + 4;
            match osc_terminator(&buf[start..]) {
                Some((end, after)) => {
                    if let Some(path) = parse_osc7(&buf[start..start + end]) {
                        found = Some(path);
                    }
                    consumed = start + after;
                    from = start + after;
                }
                None => break, // incomplete sequence; keep it for next time
            }
        }
        if consumed > 0 {
            self.osc_buf.drain(..consumed.min(self.osc_buf.len()));
        }
        if let Some(path) = found {
            self.cwd = Some(path);
        }
    }

    /// Sends raw bytes to the backend.
    pub fn write(&mut self, data: &[u8]) {
        if self.exited {
            return;
        }
        if let Err(e) = self.backend.write(data) {
            log::warn!("terminal write failed: {e}");
        }
    }

    /// Sends user input: also jumps back to the bottom and clears the selection.
    pub(crate) fn input(&mut self, data: &[u8]) {
        self.term.scroll_display(Scroll::Bottom);
        self.term.selection = None;
        // Record for multi-exec broadcast (only real user input, not responses).
        self.broadcast_buf.extend_from_slice(data);
        self.write(data);
    }

    /// Drains and returns user input entered since the last call (for multi-exec).
    pub fn take_broadcast(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.broadcast_buf)
    }

    /// Pastes text, wrapped in bracketed-paste markers if the program asked for them.
    pub fn paste(&mut self, text: &str) {
        let data = if self.term.mode().contains(TermMode::BRACKETED_PASTE) {
            // Strip ESC so pasted text can't end the bracketed paste early.
            format!("\x1b[200~{}\x1b[201~", text.replace('\x1b', ""))
        } else {
            text.replace("\r\n", "\r").replace('\n', "\r")
        };
        self.input(data.as_bytes());
    }

    pub fn resize(&mut self, size: TermSize) {
        if size == self.size {
            return;
        }
        self.size = size;
        self.term.resize(Dims(size));
        if let Err(e) = self.backend.resize(size) {
            log::warn!("terminal resize failed: {e}");
        }
    }

    pub fn selection_text(&self) -> Option<String> {
        self.term.selection_to_string().filter(|s| !s.is_empty())
    }

    /// The visible screen as plain text, one line per row, trailing spaces trimmed.
    pub fn screen_text(&self) -> String {
        self.text_range(0)
    }

    /// The scrollback history plus the visible screen, as plain text.
    pub fn full_text(&self) -> String {
        let history = self.term.grid().history_size() as i32;
        self.text_range(history)
    }

    /// Grid rows from `history` lines above the screen top through the last
    /// visible row, as plain text (trailing spaces trimmed per line).
    fn text_range(&self, history: i32) -> String {
        let grid = self.term.grid();
        let lines: Vec<String> = (-history..grid.screen_lines() as i32)
            .map(|row| {
                let line: String = (0..grid.columns())
                    .map(|col| &grid[Line(row)][Column(col)])
                    .filter(|cell| !cell.flags.contains(Flags::WIDE_CHAR_SPACER))
                    .map(|cell| cell.c)
                    .collect();
                line.trim_end().to_owned()
            })
            .collect();
        lines.join("\n").trim_end().to_owned()
    }
}

/// Finds the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Finds an OSC terminator (BEL or ESC `\`) in `buf`, returning the index where
/// the payload ends and the index just past the terminator.
fn osc_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    for (i, &b) in buf.iter().enumerate() {
        if b == 0x07 {
            return Some((i, i + 1));
        }
        if b == 0x1b && buf.get(i + 1) == Some(&b'\\') {
            return Some((i, i + 2));
        }
    }
    None
}

/// Parses an OSC 7 payload (`file://host/path`, percent-encoded) into a path.
fn parse_osc7(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let rest = text.strip_prefix("file://")?;
    // Drop the host component (up to the first '/'), keeping the path.
    let path = &rest[rest.find('/')?..];
    let decoded = percent_decode(path);
    (!decoded.is_empty()).then_some(decoded)
}

/// Decodes `%XX` escapes in a percent-encoded string (UTF-8 aware, lenient).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::LocalPty;

    /// Backend that records what the terminal writes to it.
    struct FakeBackend(Arc<Mutex<Vec<u8>>>);

    impl Backend for FakeBackend {
        fn write(&mut self, data: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        fn resize(&mut self, _size: TermSize) -> io::Result<()> {
            Ok(())
        }
    }

    fn fake_terminal() -> (Terminal, Sender<BackendEvent>, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = mpsc::channel();
        let term = Terminal::new(Box::new(FakeBackend(written.clone())), rx, TermSize::default());
        (term, tx, written)
    }

    #[test]
    fn renders_output_and_tracks_title() {
        let (mut term, tx, _) = fake_terminal();
        tx.send(BackendEvent::Output(b"\x1b]0;my title\x07\x1b[31mhello\x1b[0m\r\nworld".to_vec()))
            .unwrap();
        term.process(&egui::Context::default());
        assert_eq!(term.screen_text(), "hello\nworld");
        assert_eq!(term.title(), "my title");
    }

    #[test]
    fn answers_device_attribute_queries() {
        let (mut term, tx, written) = fake_terminal();
        tx.send(BackendEvent::Output(b"\x1b[c".to_vec())).unwrap();
        term.process(&egui::Context::default());
        assert!(written.lock().unwrap().starts_with(b"\x1b[?"));
    }

    #[test]
    fn tracks_cwd_from_osc7() {
        let (mut term, tx, _) = fake_terminal();
        tx.send(BackendEvent::Output(b"\x1b]7;file://host/var/log\x07ls\r\n".to_vec())).unwrap();
        term.process(&egui::Context::default());
        assert_eq!(term.cwd(), Some("/var/log"));
        // A later update (ESC-\ terminator, percent-encoded space) replaces it.
        tx.send(BackendEvent::Output(b"\x1b]7;file://host/tmp/a%20b\x1b\\".to_vec())).unwrap();
        term.process(&egui::Context::default());
        assert_eq!(term.cwd(), Some("/tmp/a b"));
    }

    #[test]
    fn bracketed_paste_wraps_text() {
        let (mut term, tx, written) = fake_terminal();
        tx.send(BackendEvent::Output(b"\x1b[?2004h".to_vec())).unwrap();
        term.process(&egui::Context::default());
        term.paste("ls\n\x1b");
        assert_eq!(written.lock().unwrap().as_slice(), b"\x1b[200~ls\n\x1b[201~");
    }

    #[cfg(unix)]
    #[test]
    fn runs_a_real_shell() {
        let (pty, rx) = LocalPty::spawn(TermSize::default(), || {}).unwrap();
        let mut term = Terminal::new(Box::new(pty), rx, TermSize::default());
        let ctx = egui::Context::default();
        term.write(b"echo wazowski-$((6*7))\r");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !term.screen_text().contains("wazowski-42") {
            assert!(Instant::now() < deadline, "shell output never arrived:\n{}", term.screen_text());
            std::thread::sleep(Duration::from_millis(50));
            term.process(&ctx);
        }

        term.write(b"exit\r");
        while !term.has_exited() {
            assert!(Instant::now() < deadline, "shell did not exit");
            std::thread::sleep(Duration::from_millis(50));
            term.process(&ctx);
        }
    }
}
