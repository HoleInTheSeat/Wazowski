#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod backup;
mod conn_log;
mod connect;
mod git;
mod highlights;
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

fn main() -> eframe::Result {
    conn_log::init();

    // Single-instance guard, unless the user allowed multiple instances.
    let settings = Settings::load_or_default();
    let instance_lock = if settings.allow_multiple_instances {
        None
    } else {
        match acquire_instance_lock() {
            Some(lock) => Some(lock),
            None => {
                eprintln!(
                    "Wazowski is already running. Enable \"Allow multiple instances\" in \
                     Settings to run more than one."
                );
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
        Box::new(move |cc| Ok(Box::new(App::new(&cc.egui_ctx, instance_lock)))),
    )
}
