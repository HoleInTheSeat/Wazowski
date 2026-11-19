use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

use crate::backend::{Backend, BackendEvent, TermSize};

/// A shell running on this machine in a pseudo-terminal.
pub struct LocalPty {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl LocalPty {
    /// Starts the user's default shell. `wake` is called from the reader thread
    /// whenever new output is available, so the UI can repaint.
    pub fn spawn(
        size: TermSize,
        wake: impl Fn() + Send + 'static,
    ) -> anyhow::Result<(Self, Receiver<BackendEvent>)> {
        Self::spawn_cmd(size, CommandBuilder::new_default_prog(), wake)
    }

    /// Starts a specific program (rather than the default shell) in a PTY —
    /// used, for example, to run `tmux attach` so a tmux session appears as an
    /// ordinary terminal tab. The terminal env (`TERM`, `COLORTERM`) and the
    /// home working directory are applied just as for [`spawn`].
    pub fn spawn_program(
        size: TermSize,
        program: &str,
        args: &[String],
        wake: impl Fn() + Send + 'static,
    ) -> anyhow::Result<(Self, Receiver<BackendEvent>)> {
        let mut cmd = CommandBuilder::new(program);
        cmd.args(args);
        Self::spawn_cmd(size, cmd, wake)
    }

    /// Shared launcher: opens a PTY, applies the terminal environment, spawns
    /// `cmd`, and wires up the reader thread.
    fn spawn_cmd(
        size: TermSize,
        mut cmd: CommandBuilder,
        wake: impl Fn() + Send + 'static,
    ) -> anyhow::Result<(Self, Receiver<BackendEvent>)> {
        let pair = native_pty_system().openpty(pty_size(size))?;

        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        if let Some(home) = std::env::home_dir() {
            cmd.cwd(home);
        }
        let child = pair.slave.spawn_command(cmd)?;
        // Keeping the slave open would stop us from seeing EOF when the shell exits.
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;
        let (tx, rx) = mpsc::channel();

        thread::Builder::new().name("pty-reader".into()).spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(BackendEvent::Output(buf[..n].to_vec())).is_err() {
                            return;
                        }
                        wake();
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    // Linux reports EIO once the shell has exited.
                    Err(_) => break,
                }
            }
            let _ = tx.send(BackendEvent::Exited);
            wake();
        })?;

        Ok((Self { master: pair.master, writer, child }, rx))
    }
}

impl Backend for LocalPty {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()
    }

    fn resize(&mut self, size: TermSize) -> io::Result<()> {
        self.master.resize(pty_size(size)).map_err(io::Error::other)
    }
}

impl Drop for LocalPty {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn pty_size(size: TermSize) -> PtySize {
    PtySize {
        rows: size.rows,
        cols: size.cols,
        pixel_width: size.cols.saturating_mul(size.cell_width),
        pixel_height: size.rows.saturating_mul(size.cell_height),
    }
}
