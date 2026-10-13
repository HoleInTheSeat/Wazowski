use eframe::egui::{self, Key, KeyboardShortcut, Modifiers};
use wazowski_term::{LocalPty, TermSize, Terminal, TerminalView};

const NEW_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::T);
const CLOSE_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::W);
const NEXT_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::PageDown);
const PREV_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::PageUp);

fn main() -> eframe::Result {
    env_logger::init();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Wazowski")
            .with_app_id("wazowski")
            .with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native("Wazowski", options, Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))))
}

struct App {
    tabs: Vec<Terminal>,
    active: usize,
    error: Option<String>,
}

impl App {
    fn new(ctx: &egui::Context) -> Self {
        let mut app = Self { tabs: Vec::new(), active: 0, error: None };
        app.open_local_shell(ctx);
        app
    }

    fn open_local_shell(&mut self, ctx: &egui::Context) {
        let size = TermSize::default();
        let ctx = ctx.clone();
        match LocalPty::spawn(size, move || ctx.request_repaint()) {
            Ok((pty, output)) => {
                self.tabs.push(Terminal::new(Box::new(pty), output, size));
                self.active = self.tabs.len() - 1;
            }
            Err(e) => self.error = Some(format!("Could not start a shell: {e:#}")),
        }
    }

    fn close_tab(&mut self, index: usize) {
        self.tabs.remove(index);
        if self.active >= index && self.active > 0 {
            self.active -= 1;
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let (new, close, next, prev) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&NEW_TAB),
                i.consume_shortcut(&CLOSE_TAB),
                i.consume_shortcut(&NEXT_TAB),
                i.consume_shortcut(&PREV_TAB),
            )
        });
        if new {
            self.open_local_shell(ctx);
        }
        if close && !self.tabs.is_empty() {
            self.close_tab(self.active);
        }
        if !self.tabs.is_empty() {
            let n = self.tabs.len();
            if next {
                self.active = (self.active + 1) % n;
            }
            if prev {
                self.active = (self.active + n - 1) % n;
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("Terminal", |ui| {
                let new = egui::Button::new("New local shell").shortcut_text(ui.ctx().format_shortcut(&NEW_TAB));
                if ui.add(new).clicked() {
                    self.open_local_shell(ui.ctx());
                }
                let close = egui::Button::new("Close tab").shortcut_text(ui.ctx().format_shortcut(&CLOSE_TAB));
                if ui.add_enabled(!self.tabs.is_empty(), close).clicked() {
                    self.close_tab(self.active);
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }

    fn tab_strip(&mut self, ui: &mut egui::Ui) {
        let mut close = None;
        ui.horizontal_wrapped(|ui| {
            for (i, term) in self.tabs.iter().enumerate() {
                let title: String = term.title().chars().take(32).collect();
                if ui.selectable_label(i == self.active, title).clicked() {
                    self.active = i;
                }
                if ui.small_button("×").on_hover_text("Close tab").clicked() {
                    close = Some(i);
                }
                ui.separator();
            }
            if ui.button("+").on_hover_text("New local shell").clicked() {
                self.open_local_shell(ui.ctx());
            }
        });
        if let Some(i) = close {
            self.close_tab(i);
        }
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.heading("Wazowski");
            ui.add_space(12.0);
            if ui.button("New local shell").clicked() {
                self.open_local_shell(ui.ctx());
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Tabs close themselves when their shell exits.
        let before = self.tabs.len();
        self.tabs.retain(|t| !t.has_exited());
        if self.tabs.len() != before {
            self.active = self.active.min(self.tabs.len().saturating_sub(1));
        }

        self.shortcuts(ui.ctx());

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::top("tabs").show(ui, |ui| self.tab_strip(ui));
        if let Some(error) = self.error.clone() {
            egui::Panel::bottom("error").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                    if ui.small_button("Dismiss").clicked() {
                        self.error = None;
                    }
                });
            });
        }

        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| {
            match self.tabs.get_mut(self.active) {
                Some(term) => {
                    TerminalView::new(term).show(ui);
                }
                None => self.welcome(ui),
            }
        });
    }
}
