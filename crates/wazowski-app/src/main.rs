#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backup;
mod conn_log;
mod connect;
mod git;
mod highlights;
mod icons;
mod keybinds;
mod macros;
mod network;
mod panes;
mod remote_view;
mod settings;
mod sftp_ui;
mod smb_ui;
mod sources;
mod servers_ui;
mod update;
mod uri;

use std::fs::{File, OpenOptions};

use app::App;
use fs2::FileExt;

use crate::settings::Settings;

/// Tries to take the single-instance lock. `Some(file)` must be kept alive for
/// the whole process (dropping it releases the lock); `None` means another
/// instance already holds it.
fn acquire_instance_lock() -> Option<File> {
    let path = Settings::default_path().ok()?.with_file_name("instance.lock");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(&path).ok()?;
    file.try_lock_exclusive().ok().map(|()| file)
}

/// Acquires the single-instance lock, retrying when this is a post-update
/// relaunch (`--relaunched`): the instance that spawned us is exiting but may
/// still hold the lock for a moment. Retries up to 5 times, 1s apart, so the
/// handed-off launch reliably takes over. A normal launch tries just once.
fn acquire_instance_lock_retrying(relaunched: bool) -> Option<File> {
    let attempts = if relaunched { 5 } else { 1 };
    for attempt in 0..attempts {
        if let Some(lock) = acquire_instance_lock() {
            return Some(lock);
        }
        if attempt + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    None
}

/// On macOS a Finder/`.app` launch inherits only a minimal PATH that omits
/// Homebrew, so the app can't find `brew` (or brew-installed tools like iperf3,
/// smbclient, jq, git). Prepend the standard Homebrew bin dirs that exist, so
/// detection and spawning work the same as from a login shell. No-op elsewhere.
fn augment_homebrew_path() {
    if !cfg!(target_os = "macos") {
        return;
    }
    use std::path::PathBuf;
    let cur = std::env::var_os("PATH").unwrap_or_default();
    let existing: Vec<PathBuf> = std::env::split_paths(&cur).collect();
    let mut dirs: Vec<PathBuf> = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin"]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_dir() && !existing.contains(p))
        .collect();
    if dirs.is_empty() {
        return;
    }
    dirs.extend(existing);
    if let Ok(joined) = std::env::join_paths(dirs) {
        // Safety: called at the very top of main(), before any threads are spawned.
        unsafe { std::env::set_var("PATH", joined) };
    }
}

fn main() -> eframe::Result {
    // Must run before anything spawns threads (it mutates the process environment).
    augment_homebrew_path();
    conn_log::init();

    // A connection URI argument (ssh:// or telnet://), e.g. from a browser.
    let launch_uri = std::env::args().skip(1).find(|a| uri::is_connect_uri(a));
    // A relaunch after an in-app update passes `--relaunched`, so we wait for the
    // previous instance to release the single-instance lock instead of bailing.
    let relaunched = std::env::args().any(|a| a == "--relaunched");

    // Single-instance guard, unless the user allowed multiple instances.
    let settings = Settings::load_or_default();
    let instance_lock = if settings.allow_multiple_instances {
        None
    } else {
        match acquire_instance_lock_retrying(relaunched) {
            Some(lock) => Some(lock),
            // A relaunch that still can't get the lock after retrying: the old
            // instance never exited. Tell the user rather than vanishing.
            None if relaunched => {
                rfd::MessageDialog::new()
                    .set_level(rfd::MessageLevel::Error)
                    .set_title("Wazowski")
                    .set_description(
                        "Wazowski couldn't relaunch after updating — the previous \
                         instance is still running. Please close it and open \
                         Wazowski again.",
                    )
                    .show();
                return Ok(());
            }
            None => {
                // Another instance owns the window. If we were launched to open a
                // URI, hand it off so it opens there (a new tab) instead of here.
                match &launch_uri {
                    Some(u) => {
                        if let Err(e) = uri::write_to_inbox(u) {
                            eprintln!("Could not hand off the connection to Wazowski: {e}");
                        }
                    }
                    None => eprintln!(
                        "Wazowski is already running. Enable \"Allow multiple instances\" in \
                         Settings to run more than one."
                    ),
                }
                return Ok(());
            }
        }
    };

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Wazowski")
        .with_app_id("wazowski")
        .with_decorations(false)
        .with_inner_size([1200.0, 760.0])
        .with_min_inner_size([640.0, 400.0]);
    // The window/taskbar icon, embedded from icon.png at the repo root.
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../../../icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "Wazowski",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(&cc.egui_ctx, instance_lock, launch_uri)))),
    )
}
