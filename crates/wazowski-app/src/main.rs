#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod conn_log;
mod connect;
mod git;
mod sftp_ui;
mod sources;
mod servers_ui;

use app::App;

fn main() -> eframe::Result {
    conn_log::init();
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Wazowski")
        .with_app_id("wazowski")
        .with_inner_size([1200.0, 760.0])
        .with_min_inner_size([640.0, 400.0]);
    // The window/taskbar icon, embedded from icon.png at the repo root.
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../../../icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native("Wazowski", options, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))))
}
