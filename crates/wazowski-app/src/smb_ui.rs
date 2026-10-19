//! SMB file browser for RDP sessions: browses `\\host\C$` via the system
//! `smbclient`, using the session's saved credentials. The password is fed to
//! `smbclient` on stdin (never on the command line), matching how the RDP/VNC
//! clients receive it. Operations run on worker threads and are polled per frame.

use std::process::Command;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, LazyLock};
use std::thread;

use egui::{Color32, Context, RichText};
use regex::Regex;

/// One entry in a share listing.
#[derive(Clone)]
struct SmbEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

/// Connection parameters (cloned into worker threads).
#[derive(Clone)]
struct SmbConn {
    host: String,
    share: String,
    user: String,
    password: Arc<String>,
    domain: String,
}

/// Result of a background smbclient job.
enum Outcome {
    Listed { path: String, entries: Vec<SmbEntry> },
    /// A mutating action finished; re-list the current directory.
    Acted,
    /// A read-only action finished; nothing to refresh.
    Noop,
}

struct Job {
    rx: Receiver<Result<Outcome, String>>,
}

/// SMB browser state for one RDP session.
pub struct SmbBrowser {
    conn: SmbConn,
    /// Current directory within the share, backslash-separated; empty = root.
    cwd: String,
    entries: Vec<SmbEntry>,
    selected: Option<usize>,
    status: String,
    error: Option<String>,
    job: Option<Job>,
    started: bool,
    new_folder: Option<String>,
    highlight: String,
}

impl SmbBrowser {
    /// `user`/`password`/`domain` come from the RDP session; `host` is its host.
    pub fn new(host: &str, user: &str, password: &str, domain: &str) -> Self {
        Self {
            conn: SmbConn {
                host: host.trim().to_owned(),
                share: "C$".to_owned(),
                user: user.trim().to_owned(),
                password: Arc::new(password.to_owned()),
                domain: domain.trim().to_owned(),
            },
            cwd: String::new(),
            entries: Vec::new(),
            selected: None,
            status: String::new(),
            error: None,
            job: None,
            started: false,
            new_folder: None,
            highlight: String::new(),
        }
    }

    /// The `\\host\share` path, for the panel heading.
    pub fn location(&self) -> String {
        format!("\\\\{}\\{}", self.conn.host, self.conn.share)
    }

    pub fn set_highlight(&mut self, highlight: &str) {
        self.highlight = highlight.to_lowercase();
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Spawns a background smbclient job.
    fn spawn(
        &mut self,
        ctx: &Context,
        f: impl FnOnce(&SmbConn) -> Result<Outcome, String> + Send + 'static,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        let conn = self.conn.clone();
        let repaint = ctx.clone();
        thread::Builder::new()
            .name("wz-smb".into())
            .spawn(move || {
                let _ = tx.send(f(&conn));
                repaint.request_repaint();
            })
            .expect("spawning a thread should not fail");
        self.job = Some(Job { rx });
        self.status = "Working…".into();
        self.error = None;
    }

    /// Lists `path` (backslash-separated, relative to the share root).
    fn list(&mut self, path: String, ctx: &Context) {
        self.spawn(ctx, move |conn| {
            let entries = smb_list(conn, &path)?;
            Ok(Outcome::Listed { path, entries })
        });
    }

    fn poll(&mut self, ctx: &Context) {
        let Some(job) = &self.job else { return };
        match job.rx.try_recv() {
            Err(TryRecvError::Empty) => ctx.request_repaint(),
            Ok(result) => {
                self.job = None;
                self.status.clear();
                match result {
                    Ok(Outcome::Listed { path, entries }) => {
                        self.cwd = path;
                        self.entries = entries;
                        self.selected = None;
                    }
                    Ok(Outcome::Acted) => {
                        let cwd = self.cwd.clone();
                        self.list(cwd, ctx);
                    }
                    Ok(Outcome::Noop) => {}
                    Err(e) => self.error = Some(e),
                }
            }
            Err(TryRecvError::Disconnected) => {
                self.job = None;
                self.status.clear();
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        self.poll(ctx);
        if !self.started {
            self.started = true;
            self.list(String::new(), ctx);
        }

        // Path breadcrumb + refresh.
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.busy(), egui::Button::new("⟳")).on_hover_text("Refresh").clicked()
            {
                let cwd = self.cwd.clone();
                self.list(cwd, ctx);
            }
            let up_enabled = !self.busy() && !self.cwd.is_empty();
            if ui.add_enabled(up_enabled, egui::Button::new("⬆")).on_hover_text("Up").clicked() {
                let parent = parent_path(&self.cwd);
                self.list(parent, ctx);
            }
            if ui.add_enabled(!self.busy(), egui::Button::new("＋ Folder")).clicked() {
                self.new_folder = Some(String::new());
            }
            if ui.add_enabled(!self.busy(), egui::Button::new("Upload…")).clicked() {
                self.upload(ctx);
            }
        });
        ui.label(RichText::new(format!("\\{}", self.cwd)).monospace().weak());

        if let Some(name) = &mut self.new_folder {
            let mut create = false;
            let mut cancel = false;
            ui.horizontal(|ui| {
                ui.label("New folder:");
                let r = ui.text_edit_singleline(name);
                create = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                create |= ui.button("Create").clicked();
                cancel = ui.button("Cancel").clicked();
            });
            if create {
                let name = self.new_folder.take().unwrap_or_default();
                if !name.trim().is_empty() {
                    let cwd = self.cwd.clone();
                    self.spawn(ctx, move |conn| {
                        smb_run(conn, &format!("{}mkdir \"{}\"", cd_cmd(&cwd), name.trim()))?;
                        Ok(Outcome::Acted)
                    });
                }
            } else if cancel {
                self.new_folder = None;
            }
        }

        if self.busy() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(&self.status);
            });
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        ui.separator();

        let mut action: Option<Act> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // Directories first, then files, each alphabetical.
            let mut order: Vec<usize> = (0..self.entries.len()).collect();
            order.sort_by(|&a, &b| {
                let (ea, eb) = (&self.entries[a], &self.entries[b]);
                eb.is_dir
                    .cmp(&ea.is_dir)
                    .then_with(|| ea.name.to_lowercase().cmp(&eb.name.to_lowercase()))
            });
            for i in order {
                let entry = &self.entries[i];
                let icon = if entry.is_dir { "📁" } else { "📄" };
                let label = if entry.is_dir {
                    format!("{icon} {}", entry.name)
                } else {
                    format!("{icon} {}   {}", entry.name, human_size(entry.size))
                };
                let mut text = RichText::new(label);
                if !self.highlight.is_empty() && entry.name.to_lowercase().contains(&self.highlight) {
                    text = text.color(Color32::from_rgb(240, 210, 90));
                }
                let resp = ui.selectable_label(self.selected == Some(i), text);
                if resp.clicked() {
                    self.selected = Some(i);
                }
                if resp.double_clicked() {
                    action = Some(if entry.is_dir {
                        Act::Open(entry.name.clone())
                    } else {
                        Act::Download(entry.name.clone())
                    });
                }
                resp.context_menu(|ui| {
                    if !entry.is_dir && ui.button("Download…").clicked() {
                        action = Some(Act::Download(entry.name.clone()));
                        ui.close();
                    }
                    if entry.is_dir && ui.button("Open").clicked() {
                        action = Some(Act::Open(entry.name.clone()));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Delete").clicked() {
                        action = Some(Act::Delete(entry.name.clone(), entry.is_dir));
                        ui.close();
                    }
                });
            }
        });

        match action {
            Some(Act::Open(name)) => {
                let path = join_path(&self.cwd, &name);
                self.list(path, ctx);
            }
            Some(Act::Download(name)) => self.download(&name, ctx),
            Some(Act::Delete(name, is_dir)) => {
                let cwd = self.cwd.clone();
                self.spawn(ctx, move |conn| {
                    let verb = if is_dir { "rmdir" } else { "del" };
                    smb_run(conn, &format!("{}{verb} \"{}\"", cd_cmd(&cwd), name))?;
                    Ok(Outcome::Acted)
                });
            }
            None => {}
        }
    }

    /// Downloads `name` from the current directory to a user-chosen path.
    fn download(&mut self, name: &str, ctx: &Context) {
        let Some(local) = rfd::FileDialog::new().set_file_name(name).save_file() else {
            return;
        };
        let cwd = self.cwd.clone();
        let name = name.to_owned();
        self.spawn(ctx, move |conn| {
            let local = local.to_string_lossy().replace('"', "");
            smb_run(conn, &format!("{}get \"{}\" \"{}\"", cd_cmd(&cwd), name, local))?;
            Ok(Outcome::Noop)
        });
    }

    /// Uploads a user-chosen local file into the current directory.
    fn upload(&mut self, ctx: &Context) {
        let Some(local) = rfd::FileDialog::new().pick_file() else {
            return;
        };
        let name =
            local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "upload".into());
        let cwd = self.cwd.clone();
        self.spawn(ctx, move |conn| {
            let path = local.to_string_lossy().replace('"', "");
            smb_run(conn, &format!("{}put \"{}\" \"{}\"", cd_cmd(&cwd), path, name))?;
            Ok(Outcome::Acted)
        });
    }
}

/// A row action applied after the listing is drawn.
enum Act {
    Open(String),
    Download(String),
    Delete(String, bool),
}

/// A compact human-readable byte size.
fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{size:.1} {}", UNITS[unit]) }
}

/// `cd "\path"; ` prefix for a smbclient command sequence (empty cwd → root).
fn cd_cmd(cwd: &str) -> String {
    if cwd.is_empty() { "cd \"\\\"; ".to_owned() } else { format!("cd \"\\{cwd}\"; ") }
}

/// Joins a backslash cwd with a child name.
fn join_path(cwd: &str, name: &str) -> String {
    if cwd.is_empty() { name.to_owned() } else { format!("{cwd}\\{name}") }
}

/// The parent of a backslash path (empty for a top-level entry).
fn parent_path(cwd: &str) -> String {
    match cwd.rfind('\\') {
        Some(i) => cwd[..i].to_owned(),
        None => String::new(),
    }
}

/// Runs `smbclient //host/share -c <commands>`, feeding the password on stdin.
fn smb_run(conn: &SmbConn, commands: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::Stdio;
    let unc = format!("//{}/{}", conn.host, conn.share);
    let mut cmd = Command::new("smbclient");
    cmd.arg(&unc).arg("-U").arg(&conn.user);
    if !conn.domain.is_empty() {
        cmd.arg("-W").arg(&conn.domain);
    }
    cmd.arg("-c").arg(commands);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not run smbclient (is Samba's client installed?): {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{}", conn.password);
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = if !stderr.trim().is_empty() { stderr.trim() } else { stdout.trim() };
        Err(if msg.is_empty() { "smbclient failed".to_owned() } else { msg.to_owned() })
    }
}

/// Lists a directory and parses smbclient's `ls` output.
fn smb_list(conn: &SmbConn, cwd: &str) -> Result<Vec<SmbEntry>, String> {
    let out = smb_run(conn, &format!("{}ls", cd_cmd(cwd)))?;
    Ok(parse_ls(&out))
}

/// Parses `smbclient` `ls` output lines into entries (skips `.`/`..` and the
/// trailing "blocks available" summary).
fn parse_ls(output: &str) -> Vec<SmbEntry> {
    // `  NAME   FLAGS   SIZE   Www Mmm dd hh:mm:ss yyyy`
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\s+(.+?)\s+([DAHSRN]+)\s+(\d+)\s+\w{3}\s+\w{3}\s+.+$").expect("valid regex")
    });
    let mut entries = Vec::new();
    for line in output.lines() {
        let Some(caps) = RE.captures(line) else { continue };
        let name = caps[1].to_owned();
        if name == "." || name == ".." {
            continue;
        }
        let flags = &caps[2];
        let size = caps[3].parse().unwrap_or(0);
        entries.push(SmbEntry { name, is_dir: flags.contains('D'), size });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ls_entries() {
        let out = "\
  .                                   D        0  Mon Jan  1 00:00:00 2024
  ..                                  D        0  Mon Jan  1 00:00:00 2024
  Program Files                      DR        0  Wed Nov 20 10:00:00 2024
  pagefile.sys                      AHS 2147483648  Wed Nov 20 10:00:00 2024
  setup.log                           A     1234  Wed Nov 20 10:00:00 2024

		123456 blocks of size 4096. 7890 blocks available
";
        let entries = parse_ls(out);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["Program Files", "pagefile.sys", "setup.log"]);
        assert!(entries[0].is_dir);
        assert!(!entries[2].is_dir);
        assert_eq!(entries[2].size, 1234);
    }

    #[test]
    fn paths_join_and_pop() {
        assert_eq!(join_path("", "Windows"), "Windows");
        assert_eq!(join_path("Windows", "System32"), "Windows\\System32");
        assert_eq!(parent_path("Windows\\System32"), "Windows");
        assert_eq!(parent_path("Windows"), "");
        assert_eq!(cd_cmd(""), "cd \"\\\"; ");
        assert_eq!(cd_cmd("Windows"), "cd \"\\Windows\"; ");
    }
}
