//! In-window remote-desktop tab: renders a [`RemoteHandle`]'s framebuffer into
//! an egui texture and forwards mouse/keyboard input back to the backend.
//!
//! The image is letterboxed to fit the tab while preserving aspect ratio; pointer
//! coordinates are mapped back into remote pixels, and keyboard input is converted
//! to X11 keysyms (what RFB expects).

use egui::{Color32, Key, Modifiers, Sense, TextureHandle, TextureOptions};
use wazowski_remote::{RemoteEvent, RemoteHandle, RemoteInput};

/// Which protocol a remote tab speaks (controls which toolbar ops are offered).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RemoteKind {
    Rdp,
    Vnc,
}

/// Connection state shown in the tab.
enum Status {
    Connecting,
    Connected,
    Ended(String),
}

/// A live remote-desktop tab.
pub struct RemoteTab {
    handle: RemoteHandle,
    kind: RemoteKind,
    texture: Option<TextureHandle>,
    last_seq: u64,
    /// Remote resolution in pixels.
    size: (u16, u16),
    status: Status,
    view_only: bool,
    /// Current RFB button mask (bit0 left, bit1 middle, bit2 right).
    buttons: u8,
    /// Modifier state last frame, to synthesize modifier key up/down.
    mods: Modifiers,
}

impl RemoteTab {
    pub fn new(handle: RemoteHandle, view_only: bool, kind: RemoteKind) -> Self {
        Self {
            handle,
            kind,
            texture: None,
            last_seq: 0,
            size: (0, 0),
            status: Status::Connecting,
            view_only,
            buttons: 0,
            mods: Modifiers::default(),
        }
    }

    pub fn kind(&self) -> RemoteKind {
        self.kind
    }

    /// Whether the session has stopped (errored or disconnected).
    pub fn ended(&self) -> bool {
        matches!(self.status, Status::Ended(_))
    }

    /// The current framebuffer as `(width, height, rgba)`, if any pixels exist.
    pub fn snapshot(&self) -> Option<(usize, usize, Vec<u8>)> {
        self.handle.with_frame(|f| {
            (f.width > 0 && !f.rgba.is_empty()).then(|| (f.width, f.height, f.rgba.clone()))
        })
    }

    /// Presses the given keysyms in order, then releases them in reverse — e.g.
    /// a Ctrl+Alt+Del or Windows-key chord.
    pub fn send_chord(&self, keysyms: &[u32]) {
        for &k in keysyms {
            self.handle.send_input(RemoteInput::Key { keysym: k, down: true });
        }
        for &k in keysyms.iter().rev() {
            self.handle.send_input(RemoteInput::Key { keysym: k, down: false });
        }
    }

    /// Types `text` into the session as individual key presses (newlines become
    /// Enter, tabs become Tab). Each character goes down then up.
    pub fn type_text(&self, text: &str) {
        for ch in text.chars() {
            let keysym = match ch {
                '\n' => 0xff0d, // Enter
                '\r' => continue,
                '\t' => 0xff09, // Tab
                c if (c as u32) <= 0xff => c as u32,
                c => 0x0100_0000 + c as u32, // X11 Unicode keysym
            };
            self.handle.send_input(RemoteInput::Key { keysym, down: true });
            self.handle.send_input(RemoteInput::Key { keysym, down: false });
        }
    }

    /// Draws the tab and processes input. Schedules the next repaint (~30 fps)
    /// so frames flow without pegging the render loop; input still triggers
    /// immediate repaints, so interaction stays snappy.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(33));

        for ev in self.handle.poll_events() {
            match ev {
                RemoteEvent::Resized(w, h) => {
                    self.size = (w, h);
                    self.status = Status::Connected;
                }
                RemoteEvent::Error(e) => self.status = Status::Ended(e),
                RemoteEvent::Disconnected => {
                    if !self.ended() {
                        self.status = Status::Ended("Disconnected".to_owned());
                    }
                }
            }
        }

        self.sync_texture(ui);

        if let Status::Ended(msg) = &self.status {
            let msg = msg.clone();
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new(format!("Session ended: {msg}")).weak());
            });
            return;
        }

        let Some(texture) = &self.texture else {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("Connecting…").weak());
            });
            return;
        };

        // Letterbox the framebuffer into the available area.
        let avail = ui.available_size();
        let (resp, painter) = ui.allocate_painter(avail, Sense::click_and_drag());
        let (sw, sh) = (self.size.0.max(1) as f32, self.size.1.max(1) as f32);
        let scale = (resp.rect.width() / sw).min(resp.rect.height() / sh).max(f32::EPSILON);
        let draw = egui::vec2(sw * scale, sh * scale);
        let draw_rect = egui::Rect::from_center_size(resp.rect.center(), draw);
        painter.image(
            texture.id(),
            draw_rect,
            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            Color32::WHITE,
        );

        if self.view_only {
            return;
        }
        if resp.clicked() || resp.dragged() {
            resp.request_focus();
        }
        self.handle_pointer(ui, &resp, draw_rect, scale);
        if resp.has_focus() {
            self.handle_keyboard(ui);
        }
    }

    /// Uploads the latest framebuffer to the texture when it changed.
    ///
    /// Never blocks the UI thread on the backend's frame lock (uses a try-lock,
    /// skipping this repaint if the backend is mid-write), and builds the image
    /// under the lock but performs the GPU upload *after* releasing it — so a
    /// large/slow remote update can't freeze the window.
    fn sync_texture(&mut self, ui: &egui::Ui) {
        let image = self.handle.try_with_frame(|frame| {
            if frame.width == 0 || frame.seq == self.last_seq {
                return None;
            }
            self.last_seq = frame.seq;
            if self.size == (0, 0) {
                self.size = (frame.width as u16, frame.height as u16);
            }
            Some(egui::ColorImage::from_rgba_unmultiplied(
                [frame.width, frame.height],
                &frame.rgba,
            ))
        });
        // `try_with_frame` is `None` when the lock was busy; the inner `Option`
        // is `None` when nothing changed. Only upload on a real new frame.
        if let Some(Some(image)) = image {
            match &mut self.texture {
                Some(tex) => tex.set(image, TextureOptions::default()),
                None => {
                    self.texture =
                        Some(ui.ctx().load_texture("remote-fb", image, TextureOptions::default()));
                }
            }
        }
    }

    fn handle_pointer(
        &mut self,
        ui: &egui::Ui,
        resp: &egui::Response,
        draw_rect: egui::Rect,
        scale: f32,
    ) {
        let Some(pos) = resp.hover_pos().or_else(|| resp.interact_pointer_pos()) else {
            return;
        };
        if !draw_rect.contains(pos) {
            return;
        }
        let rx = ((pos.x - draw_rect.min.x) / scale).clamp(0.0, self.size.0.max(1) as f32 - 1.0);
        let ry = ((pos.y - draw_rect.min.y) / scale).clamp(0.0, self.size.1.max(1) as f32 - 1.0);
        let (x, y) = (rx as u16, ry as u16);

        let mut mask = 0u8;
        ui.input(|i| {
            if i.pointer.primary_down() {
                mask |= 0b0000_0001;
            }
            if i.pointer.middle_down() {
                mask |= 0b0000_0010;
            }
            if i.pointer.secondary_down() {
                mask |= 0b0000_0100;
            }
        });

        // Only send when something changed, to avoid flooding the server.
        if mask != self.buttons {
            self.buttons = mask;
            self.handle.send_input(RemoteInput::Pointer { x, y, buttons: mask });
        } else if resp.hovered() {
            self.handle.send_input(RemoteInput::Pointer { x, y, buttons: mask });
        }

        // Scroll wheel: press + release the wheel button bit at the cursor.
        let scroll = ui.input(|i| {
            i.events
                .iter()
                .filter_map(|e| match e {
                    egui::Event::MouseWheel { delta, .. } => Some(delta.y),
                    _ => None,
                })
                .sum::<f32>()
        });
        if scroll.abs() > 0.5 {
            let wheel = if scroll > 0.0 { 0b0000_1000 } else { 0b0001_0000 };
            self.handle.send_input(RemoteInput::Pointer { x, y, buttons: mask | wheel });
            self.handle.send_input(RemoteInput::Pointer { x, y, buttons: mask });
        }
    }

    fn handle_keyboard(&mut self, ui: &egui::Ui) {
        // Synthesize modifier up/down from state changes.
        let now = ui.input(|i| i.modifiers);
        for (was, is, keysym) in [
            (self.mods.shift, now.shift, 0xffe1),
            (self.mods.ctrl, now.ctrl, 0xffe3),
            (self.mods.alt, now.alt, 0xffe9),
        ] {
            if was != is {
                self.handle.send_input(RemoteInput::Key { keysym, down: is });
            }
        }
        self.mods = now;

        let events = ui.input(|i| i.events.clone());
        for ev in events {
            match ev {
                // Plain typing (layout/shift already resolved) when no Ctrl/Alt.
                egui::Event::Text(text) if !now.ctrl && !now.alt => {
                    for ch in text.chars() {
                        let keysym = char_keysym(ch);
                        self.handle.send_input(RemoteInput::Key { keysym, down: true });
                        self.handle.send_input(RemoteInput::Key { keysym, down: false });
                    }
                }
                // Non-text keys always; text keys only under Ctrl/Alt (combos).
                egui::Event::Key { key, pressed, repeat, .. } => {
                    if let Some(keysym) = key_keysym(key) {
                        let is_text = key_is_text(key);
                        if !is_text || now.ctrl || now.alt {
                            if repeat && !pressed {
                                continue;
                            }
                            self.handle.send_input(RemoteInput::Key { keysym, down: pressed });
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// X11 keysym for a typed character (Latin-1 maps directly; others use the
/// Unicode keysym range).
fn char_keysym(ch: char) -> u32 {
    let c = ch as u32;
    if c <= 0xff { c } else { 0x0100_0000 + c }
}

/// Whether an egui key produces text (so plain presses come via `Event::Text`).
fn key_is_text(key: Key) -> bool {
    use Key::*;
    matches!(
        key,
        A | B | C | D | E | F | G | H | I | J | K | L | M | N | O | P | Q | R | S | T | U | V | W
            | X | Y | Z
            | Num0 | Num1 | Num2 | Num3 | Num4 | Num5 | Num6 | Num7 | Num8 | Num9
            | Space
            | Minus | Plus | Equals | Comma | Period | Semicolon | Colon | Backtick | Slash
            | Backslash | OpenBracket | CloseBracket | Quote | Questionmark | Exclamationmark
    )
}

/// X11 keysym for an egui key, or `None` if unmapped.
fn key_keysym(key: Key) -> Option<u32> {
    use Key::*;
    Some(match key {
        Enter => 0xff0d,
        Tab => 0xff09,
        Backspace => 0xff08,
        Escape => 0xff1b,
        Space => 0x20,
        Delete => 0xffff,
        Insert => 0xff63,
        Home => 0xff50,
        End => 0xff57,
        PageUp => 0xff55,
        PageDown => 0xff56,
        ArrowLeft => 0xff51,
        ArrowUp => 0xff52,
        ArrowRight => 0xff53,
        ArrowDown => 0xff54,
        F1 => 0xffbe,
        F2 => 0xffbf,
        F3 => 0xffc0,
        F4 => 0xffc1,
        F5 => 0xffc2,
        F6 => 0xffc3,
        F7 => 0xffc4,
        F8 => 0xffc5,
        F9 => 0xffc6,
        F10 => 0xffc7,
        F11 => 0xffc8,
        F12 => 0xffc9,
        // Letters/digits: lowercase/base keysym; the server applies Shift.
        A => 0x61, B => 0x62, C => 0x63, D => 0x64, E => 0x65, F => 0x66, G => 0x67, H => 0x68,
        I => 0x69, J => 0x6a, K => 0x6b, L => 0x6c, M => 0x6d, N => 0x6e, O => 0x6f, P => 0x70,
        Q => 0x71, R => 0x72, S => 0x73, T => 0x74, U => 0x75, V => 0x76, W => 0x77, X => 0x78,
        Y => 0x79, Z => 0x7a,
        Num0 => 0x30, Num1 => 0x31, Num2 => 0x32, Num3 => 0x33, Num4 => 0x34, Num5 => 0x35,
        Num6 => 0x36, Num7 => 0x37, Num8 => 0x38, Num9 => 0x39,
        _ => return None,
    })
}
