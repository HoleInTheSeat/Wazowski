#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod connect;
mod sftp_ui;

use app::App;

fn main() -> eframe::Result {
    env_logger::init();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Wazowski")
            .with_app_id("wazowski")
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([640.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native("Wazowski", options, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))))
}
