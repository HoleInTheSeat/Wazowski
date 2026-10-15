//! The SFTP file browser panel shown beside an active SSH tab.
//!
//! Operations run on worker threads (SFTP calls block) and are polled each
//! frame, so the UI never stalls on the network.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::SystemTime;

use egui::{Context, RichText};
use wazowski_ssh::{FileEntry, Sftp};

/// Result of a background SFTP job.
enum JobOutcome {
    /// A directory listing for `cwd`.
    Listed { cwd: String, entries: Vec<FileEntry> },
    /// A file was downloaded to a temp path to be opened locally.
    Opened { remote: String, local: PathBuf },
    /// A mutating action finished; the browser should refresh.
    Acted,
    /// A read-only action finished; nothing to refresh.
    Noop,
}

/// A remote file downloaded to a temp path and opened locally, watched for edits.
struct OpenFile {
    remote: String,
    local: PathBuf,
    /// The temp file's modified time + size as of the last download/upload, to
    /// detect edits (either changing flags the file).
    seen: (Option<SystemTime>, u64),
    /// Set once a local edit is detected, until the user uploads or dismisses.
    changed: bool,
}

/// A local file's (modified time, size), for change detection.
fn mtime(path: &std::path::Path) -> (Option<SystemTime>, u64) {
    match std::fs::metadata(path) {
        Ok(m) => (m.modified().ok(), m.len()),
        Err(_) => (None, 0),
    }
}

/// A running background job.
struct Job {
    rx: Receiver<Result<JobOutcome, String>>,
}

/// Browser state for one SSH session.
pub struct FileBrowser {
    sftp: Sftp,
    cwd: String,
    entries: Vec<FileEntry>,
    selected: Option<usize>,
    status: String,
    job: Option<Job>,
    /// Set once the initial home-directory listing has been kicked off.
    started: bool,
    /// Inline "new folder" name input, shown when `Some`.
    new_folder: Option<String>,
    /// Temp directory holding files opened from this session (cleared on drop).
    temp_dir: PathBuf,
    /// Remote files opened locally, watched for edits.
    open_files: Vec<OpenFile>,
    /// Whether the panel follows the terminal's current directory.
    follow: bool,
}

impl FileBrowser {
    pub fn new(sftp: Sftp) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let temp_dir = std::env::temp_dir().join(format!(
            "wazowski-sftp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            sftp,
            cwd: ".".into(),
            entries: Vec::new(),
            selected: None,
            status: String::new(),
            job: None,
            started: false,
            new_folder: None,
            temp_dir,
            open_files: Vec::new(),
            follow: false,
        }
    }

    /// Whether "follow terminal directory" is enabled.
    pub fn following(&self) -> bool {
        self.follow
    }

    /// Navigates to `path` if it differs from the current directory (used to
    /// follow the terminal's working directory). No-op while busy.
    pub fn follow_path(&mut self, path: &str, ctx: &Context) {
        if self.busy() || path.is_empty() || path == self.cwd {
            return;
        }
        self.list(path.to_owned(), ctx);
    }

    /// Spawns a job that lists `path`, resolving it to an absolute path first.
    fn list(&mut self, path: String, ctx: &Context) {
        self.spawn(ctx, move |sftp| {
            let cwd = sftp.canonicalize(&path)?;
            let entries = sftp.list_dir(&cwd)?;
            Ok(JobOutcome::Listed { cwd, entries })
        });
    }

    /// Spawns a background job running `f` against the SFTP session.
    fn spawn(
        &mut self,
        ctx: &Context,
        f: impl FnOnce(&Sftp) -> Result<JobOutcome, String> + Send + 'static,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let sftp = self.sftp.clone();
        let repaint = ctx.clone();
        thread::Builder::new()
            .name("wz-sftp".into())
            .spawn(move || {
                let _ = tx.send(f(&sftp));
                repaint.request_repaint();
            })
            .expect("spawning a thread should not fail");
        self.job = Some(Job { rx });
        self.status = "Working…".into();
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Checks a running job for completion.
    fn poll(&mut self, ctx: &Context) {
        let Some(job) = &self.job else { return };
        match job.rx.try_recv() {
            Err(TryRecvError::Empty) => {
                ctx.request_repaint();
            }
            Ok(Ok(JobOutcome::Listed { cwd, entries })) => {
                self.cwd = cwd;
                self.entries = entries;
                self.selected = None;
                self.status.clear();
                self.job = None;
            }
            Ok(Ok(JobOutcome::Opened { remote, local })) => {
                self.job = None;
                self.status.clear();
                match open::that(&local) {
                    Ok(()) => self.track_open(remote, local),
                    Err(e) => self.status = format!("could not open the file: {e}"),
                }
            }
            Ok(Ok(JobOutcome::Acted)) => {
                self.job = None;
                self.refresh(ctx);
            }
            Ok(Ok(JobOutcome::Noop)) => {
                self.status.clear();
                self.job = None;
            }
            Ok(Err(e)) => {
                self.status = e;
                self.job = None;
            }
            Err(TryRecvError::Disconnected) => {
                self.status = "the operation did not complete".into();
                self.job = None;
            }
        }
    }

    fn refresh(&mut self, ctx: &Context) {
        let cwd = self.cwd.clone();
        self.list(cwd, ctx);
    }

    /// Renders the panel.
    pub fn ui(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        if !self.started {
            self.started = true;
            self.list(".".into(), ctx);
        }
        self.poll(ctx);

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Files");
            if self.busy() {
                ui.spinner();
            }
        });
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.busy(), |ui| {
                if ui.button("⬆").on_hover_text("Parent directory").clicked() {
                    self.go_up(ctx);
                }
                if ui.button("⟳").on_hover_text("Refresh").clicked() {
                    self.refresh(ctx);
                }
                if ui.button("Upload").on_hover_text("Upload a local file here").clicked() {
                    self.upload(ctx);
                }
                if ui.button("New folder").clicked() {
                    self.new_folder = Some(String::new());
                }
            });
        });
        ui.checkbox(&mut self.follow, "Follow terminal directory")
            .on_hover_text("When the shell changes directory (cd), follow it here");

        ui.add_space(2.0);
        ui.label(RichText::new(&self.cwd).monospace().weak());
        ui.separator();

        if let Some(name) = &mut self.new_folder {
            let mut create = false;
            let mut cancel = false;
            ui.horizontal(|ui| {
                ui.label("Name:");
                let resp = ui.text_edit_singleline(name);
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    create = true;
                }
                if ui.button("Create").clicked() {
                    create = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
            if create {
                self.create_folder(ctx);
            } else if cancel {
                self.new_folder = None;
            }
            ui.separator();
        }

        // Watch opened files for local edits, and keep polling while any are open.
        self.watch_open_files();
        if !self.open_files.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        // Opened-files list and status live in a bottom strip so they stay visible
        // regardless of how long the file list is; the list fills the space above.
        if !self.open_files.is_empty() || !self.status.is_empty() {
            egui::Panel::bottom("sftp-bottom").show(ui, |ui| {
                self.open_files_panel(ui, ctx);
                if !self.status.is_empty() {
                    ui.separator();
                    ui.label(RichText::new(&self.status).color(ui.visuals().warn_fg_color));
                }
            });
        }
        self.entry_list(ui, ctx);
    }

    fn entry_list(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        let mut navigate_into = None;
        let mut download_file = None;

        egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
            for (i, entry) in self.entries.iter().enumerate() {
                let icon = if entry.is_dir { "📁" } else { "📄" };
                let label = if entry.is_dir {
                    format!("{icon} {}", entry.name)
                } else {
                    format!("{icon} {}  ({})", entry.name, human_size(entry.size))
                };
                let resp = ui.selectable_label(self.selected == Some(i), label);
                if resp.clicked() {
                    self.selected = Some(i);
                }
                if resp.double_clicked() {
                    if entry.is_dir {
                        navigate_into = Some(entry.name.clone());
                    } else {
                        download_file = Some((entry.name.clone(), entry.size));
                    }
                }
                let resp = resp.on_hover_text(if entry.is_dir {
                    "Double-click to open"
                } else {
                    "Double-click to open locally; edits can be uploaded back"
                });
                let _ = resp;
            }
        });

        if let Some(name) = navigate_into {
            let target = join(&self.cwd, &name);
            self.list(target, ctx);
        }
        if let Some((name, _)) = download_file {
            self.open_file(&name, ctx);
        }

        ui.add_space(4.0);
        let has_selection = self.selected.is_some() && !self.busy();
        ui.horizontal(|ui| {
            ui.add_enabled_ui(has_selection, |ui| {
                if ui.button("Download").clicked()
                    && let Some(entry) = self.selected_entry()
                    && !entry.is_dir
                {
                    let name = entry.name.clone();
                    self.download(&name, ctx);
                }
                if ui.button("Delete").clicked()
                    && let Some(entry) = self.selected_entry()
                {
                    let (name, is_dir) = (entry.name.clone(), entry.is_dir);
                    self.delete(&name, is_dir, ctx);
                }
            });
        });
    }

    fn selected_entry(&self) -> Option<&FileEntry> {
        self.selected.and_then(|i| self.entries.get(i))
    }

    fn go_up(&mut self, ctx: &Context) {
        let parent = parent_dir(&self.cwd);
        self.list(parent, ctx);
    }

    fn upload(&mut self, ctx: &Context) {
        let Some(local) = rfd::FileDialog::new().pick_file() else { return };
        let name = local
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "upload".into());
        let remote = join(&self.cwd, &name);
        self.spawn(ctx, move |sftp| {
            sftp.upload(local, &remote)?;
            Ok(JobOutcome::Acted)
        });
    }

    fn download(&mut self, name: &str, ctx: &Context) {
        let Some(local) = rfd::FileDialog::new().set_file_name(name).save_file() else { return };
        let remote = join(&self.cwd, name);
        self.spawn(ctx, move |sftp| {
            sftp.download(&remote, local)?;
            Ok(JobOutcome::Noop)
        });
    }

    /// Downloads a file into the temp dir and opens it with the host's default app.
    fn open_file(&mut self, name: &str, ctx: &Context) {
        if std::fs::create_dir_all(&self.temp_dir).is_err() {
            self.status = "could not create a temp directory".into();
            return;
        }
        let remote = join(&self.cwd, name);
        let local = self.temp_dir.join(name);
        let (remote_job, local_job) = (remote.clone(), local.clone());
        self.spawn(ctx, move |sftp| {
            sftp.download(&remote_job, local_job.clone())?;
            Ok(JobOutcome::Opened { remote: remote_job, local: local_job })
        });
    }

    /// Records a freshly opened file so later local edits can be detected.
    fn track_open(&mut self, remote: String, local: PathBuf) {
        let seen = mtime(&local);
        if let Some(f) = self.open_files.iter_mut().find(|f| f.remote == remote) {
            f.local = local;
            f.seen = seen;
            f.changed = false;
        } else {
            self.open_files.push(OpenFile { remote, local, seen, changed: false });
        }
    }

    /// Flags any opened file whose temp copy has changed (mtime or size) since
    /// last seen.
    fn watch_open_files(&mut self) {
        for f in &mut self.open_files {
            if f.changed {
                continue;
            }
            let now = mtime(&f.local);
            // Only flag once the file still exists (an atomic save may briefly
            // remove it) and something differs.
            if now.0.is_some() && now != f.seen {
                f.changed = true;
            }
        }
    }

    /// Lists files opened locally from this session: edited ones are flagged and
    /// can be uploaded back; any can be closed (stops watching).
    fn open_files_panel(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        if self.open_files.is_empty() {
            return;
        }
        ui.separator();
        ui.label(RichText::new("Opened files").strong());
        let mut upload: Option<usize> = None;
        let mut close: Option<usize> = None;
        for (i, f) in self.open_files.iter().enumerate() {
            let name = f.remote.rsplit('/').next().unwrap_or(&f.remote);
            ui.horizontal(|ui| {
                if f.changed {
                    ui.label(RichText::new(format!("✎ {name}")).color(ui.visuals().warn_fg_color))
                        .on_hover_text("Edited locally — upload to send changes back");
                } else {
                    ui.label(format!("📄 {name}"));
                }
                if ui
                    .add_enabled(f.changed, egui::Button::new("Upload"))
                    .on_hover_text("Upload the edited file back to the server")
                    .clicked()
                {
                    upload = Some(i);
                }
                if ui.button("Close").on_hover_text("Stop watching this file").clicked() {
                    close = Some(i);
                }
            });
        }
        if let Some(i) = upload {
            let (remote, local) =
                (self.open_files[i].remote.clone(), self.open_files[i].local.clone());
            self.open_files[i].seen = mtime(&local);
            self.open_files[i].changed = false;
            self.spawn(ctx, move |sftp| {
                sftp.upload(local, &remote)?;
                Ok(JobOutcome::Noop)
            });
        } else if let Some(i) = close {
            self.open_files.remove(i);
        }
    }

    fn delete(&mut self, name: &str, is_dir: bool, ctx: &Context) {
        let remote = join(&self.cwd, name);
        self.spawn(ctx, move |sftp| {
            sftp.remove(&remote, is_dir)?;
            Ok(JobOutcome::Acted)
        });
    }

    fn create_folder(&mut self, ctx: &Context) {
        let Some(name) = self.new_folder.take() else { return };
        let name = name.trim().to_owned();
        if name.is_empty() {
            return;
        }
        let remote = join(&self.cwd, &name);
        self.spawn(ctx, move |sftp| {
            sftp.mkdir(&remote)?;
            Ok(JobOutcome::Acted)
        });
    }
}

impl Drop for FileBrowser {
    fn drop(&mut self) {
        // Clear temp files opened from this session when the tab/program closes.
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

/// Joins a POSIX directory and a name (SFTP paths are always `/`-separated).
fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The parent of a POSIX path, or `/` at the root.
fn parent_dir(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => "/".into(),
        Some((parent, _)) => parent.to_owned(),
    }
}

/// Formats a byte count compactly (e.g. `1.4 KB`).
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_helpers() {
        assert_eq!(join("/home/u", "f"), "/home/u/f");
        assert_eq!(join("/", "f"), "/f");
        assert_eq!(join("", "f"), "/f");
        assert_eq!(parent_dir("/home/u/x"), "/home/u");
        assert_eq!(parent_dir("/home"), "/");
        assert_eq!(parent_dir("/"), "/");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
    }
}
