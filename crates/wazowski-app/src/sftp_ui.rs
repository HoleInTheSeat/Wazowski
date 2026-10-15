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
    /// Whether to periodically re-list the current directory.
    auto_refresh: bool,
    /// When the directory was last (auto-)refreshed.
    last_refresh: std::time::Instant,
    /// Inline "duplicate" prompt: (source name, new name) when active.
    duplicate: Option<(String, String)>,
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
            auto_refresh: false,
            last_refresh: std::time::Instant::now(),
            duplicate: None,
        }
    }

    /// The current auto-refresh state (persisted per session by the app).
    pub fn auto_refresh(&self) -> bool {
        self.auto_refresh
    }

    pub fn set_auto_refresh(&mut self, on: bool) {
        self.auto_refresh = on;
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
                self.last_refresh = std::time::Instant::now();
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

        // Auto-refresh the listing periodically. This runs only while the panel
        // is drawn, so it naturally pauses on tabs the user isn't viewing.
        const AUTO_REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
        if self.auto_refresh && !self.busy() && self.last_refresh.elapsed() >= AUTO_REFRESH_EVERY {
            self.refresh(ctx);
        }
        if self.auto_refresh {
            ctx.request_repaint_after(AUTO_REFRESH_EVERY);
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Files");
            if self.busy() {
                ui.spinner();
            }
        });
        // Toolbar: icon buttons with tooltips.
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.busy(), |ui| {
                if ui.button("⬆").on_hover_text("Parent directory").clicked() {
                    self.go_up(ctx);
                }
                if ui.button("⟳").on_hover_text("Refresh").clicked() {
                    self.refresh(ctx);
                }
                if ui.button("📤").on_hover_text("Upload a file here").clicked() {
                    self.upload(ctx);
                }
                let can_download = self
                    .selected
                    .and_then(|i| self.entries.get(i))
                    .is_some_and(|e| !e.is_dir);
                if ui
                    .add_enabled(can_download, egui::Button::new("📥"))
                    .on_hover_text("Download the selected file…")
                    .clicked()
                    && let Some(name) =
                        self.selected.and_then(|i| self.entries.get(i)).map(|e| e.name.clone())
                {
                    self.download(&name, ctx);
                }
                if ui.button("📁").on_hover_text("New folder").clicked() {
                    self.new_folder = Some(String::new());
                }
            });
        });
        ui.checkbox(&mut self.auto_refresh, "Auto-refresh")
            .on_hover_text("Periodically re-list this directory (only while this tab is visible)");

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

        if let Some((_, new_name)) = &mut self.duplicate {
            let mut confirm = false;
            let mut cancel = false;
            ui.horizontal(|ui| {
                ui.label("Duplicate as:");
                let resp = ui.text_edit_singleline(new_name);
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    confirm = true;
                }
                if ui.button("Copy").clicked() {
                    confirm = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
            if confirm {
                self.do_duplicate(ctx);
            } else if cancel {
                self.duplicate = None;
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
        enum Act {
            Navigate(String),
            Open(String),
            Download(String),
            Duplicate(String),
            Delete(String, bool),
        }
        let mut act = None;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
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
                    act = Some(if entry.is_dir {
                        Act::Navigate(entry.name.clone())
                    } else {
                        Act::Open(entry.name.clone())
                    });
                }
                let name = entry.name.clone();
                let is_dir = entry.is_dir;
                resp.on_hover_text(if is_dir {
                    "Double-click to open; right-click for actions"
                } else {
                    "Double-click to open locally; right-click for actions"
                })
                .context_menu(|ui| {
                    if ui.button("Open").clicked() {
                        act = Some(if is_dir { Act::Navigate(name.clone()) } else { Act::Open(name.clone()) });
                        ui.close();
                    }
                    if !is_dir {
                        if ui.button("Download…").clicked() {
                            act = Some(Act::Download(name.clone()));
                            ui.close();
                        }
                        if ui.button("Duplicate…").clicked() {
                            act = Some(Act::Duplicate(name.clone()));
                            ui.close();
                        }
                    }
                    ui.separator();
                    if ui.button("Delete").clicked() {
                        act = Some(Act::Delete(name.clone(), is_dir));
                        ui.close();
                    }
                });
            }
        });

        match act {
            Some(Act::Navigate(name)) => self.list(join(&self.cwd, &name), ctx),
            Some(Act::Open(name)) => self.open_file(&name, ctx),
            Some(Act::Download(name)) => self.download(&name, ctx),
            Some(Act::Duplicate(name)) => self.duplicate = Some((name.clone(), name)),
            Some(Act::Delete(name, is_dir)) => self.delete(&name, is_dir, ctx),
            None => {}
        }
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

    /// Lists files opened locally from this session. Right-click a file to
    /// upload edits back, delete its temp copy, or stop watching it. The header
    /// button deletes the whole temp directory.
    fn open_files_panel(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        if self.open_files.is_empty() {
            return;
        }
        enum Act {
            Upload(usize),
            DeleteLocal(usize),
            Close(usize),
            DeleteAll,
        }
        let mut act = None;
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Opened files").strong());
            if ui
                .button("🗑")
                .on_hover_text("Delete all downloaded temp files for this session")
                .clicked()
            {
                act = Some(Act::DeleteAll);
            }
        });
        for (i, f) in self.open_files.iter().enumerate() {
            let name = f.remote.rsplit('/').next().unwrap_or(&f.remote);
            let label = if f.changed {
                RichText::new(format!("✎ {name}")).color(ui.visuals().warn_fg_color)
            } else {
                RichText::new(format!("📄 {name}"))
            };
            let hover = if f.changed {
                "Edited locally — right-click to upload"
            } else {
                "Right-click for actions"
            };
            ui.selectable_label(false, label).on_hover_text(hover).context_menu(|ui| {
                if ui.add_enabled(f.changed, egui::Button::new("Upload changes")).clicked() {
                    act = Some(Act::Upload(i));
                    ui.close();
                }
                if ui.button("Delete local copy").clicked() {
                    act = Some(Act::DeleteLocal(i));
                    ui.close();
                }
                if ui.button("Stop watching").clicked() {
                    act = Some(Act::Close(i));
                    ui.close();
                }
            });
        }
        match act {
            Some(Act::Upload(i)) => {
                let (remote, local) =
                    (self.open_files[i].remote.clone(), self.open_files[i].local.clone());
                self.open_files[i].seen = mtime(&local);
                self.open_files[i].changed = false;
                self.spawn(ctx, move |sftp| {
                    sftp.upload(local, &remote)?;
                    Ok(JobOutcome::Noop)
                });
            }
            Some(Act::DeleteLocal(i)) => {
                let _ = std::fs::remove_file(&self.open_files[i].local);
                self.open_files.remove(i);
            }
            Some(Act::Close(i)) => {
                self.open_files.remove(i);
            }
            Some(Act::DeleteAll) => {
                let _ = std::fs::remove_dir_all(&self.temp_dir);
                self.open_files.clear();
            }
            None => {}
        }
    }

    fn delete(&mut self, name: &str, is_dir: bool, ctx: &Context) {
        let remote = join(&self.cwd, name);
        self.spawn(ctx, move |sftp| {
            sftp.remove(&remote, is_dir)?;
            Ok(JobOutcome::Acted)
        });
    }

    /// Copies the selected remote file to a new name in the current directory.
    fn do_duplicate(&mut self, ctx: &Context) {
        let Some((src, new_name)) = self.duplicate.take() else { return };
        let new_name = new_name.trim().to_owned();
        if new_name.is_empty() || new_name == src {
            return;
        }
        let from = join(&self.cwd, &src);
        let to = join(&self.cwd, &new_name);
        self.spawn(ctx, move |sftp| {
            sftp.copy(&from, &to)?;
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
