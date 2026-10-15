use alacritty_terminal::grid::Scroll;
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::TermMode;
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor};
use egui::{
    Align2, Color32, CursorIcon, EventFilter, FontId, Id, Key, Modifiers, MouseWheelUnit,
    PointerButton, Pos2, Rect, Response, Sense, Stroke, StrokeKind, Ui, Vec2, ViewportCommand,
    pos2, vec2,
};

use crate::backend::TermSize;
use crate::colors::{Palette, dim};
use crate::input::key_to_bytes;
use crate::terminal::Terminal;

const PADDING: f32 = 4.0;

/// Draws a [`Terminal`] filling the available space and feeds it keyboard and mouse input.
///
/// Copy/paste: selecting text copies it; Ctrl+Shift+C / Ctrl+Shift+V also work,
/// and right or middle click pastes.
pub struct TerminalView<'a> {
    terminal: &'a mut Terminal,
    font: FontId,
    interactive: bool,
    search: Option<SearchQuery>,
}

/// A find query to highlight on the terminal's visible screen.
#[derive(Clone)]
pub struct SearchQuery {
    pub needle: String,
    pub case_sensitive: bool,
}

/// Translucent marker drawn over search matches.
const SEARCH_HIGHLIGHT: Color32 = Color32::from_rgba_premultiplied(120, 110, 0, 110);

/// Maps between screen positions and terminal cells.
struct Grid {
    origin: Pos2,
    cell: Vec2,
    cols: usize,
    rows: usize,
}

impl Grid {
    fn cell_rect(&self, row: i32, col: usize, width: usize) -> Rect {
        let min = self.origin + vec2(col as f32 * self.cell.x, row as f32 * self.cell.y);
        Rect::from_min_size(min, vec2(self.cell.x * width as f32, self.cell.y))
    }

    fn point_at(&self, pos: Pos2, display_offset: usize) -> (Point, Side) {
        let rel = pos - self.origin;
        let x = (rel.x / self.cell.x).max(0.0);
        let col = (x as usize).min(self.cols - 1);
        let side = if x.fract() < 0.5 { Side::Left } else { Side::Right };
        let row = ((rel.y / self.cell.y).floor() as i32).clamp(0, self.rows as i32 - 1);
        (Point::new(Line(row - display_offset as i32), Column(col)), side)
    }
}

impl<'a> TerminalView<'a> {
    pub fn new(terminal: &'a mut Terminal) -> Self {
        Self { terminal, font: FontId::monospace(14.0), interactive: true, search: None }
    }

    pub fn font_size(mut self, size: f32) -> Self {
        self.font.size = size;
        self
    }

    /// Highlights occurrences of a find query on the visible screen.
    pub fn search(mut self, search: Option<SearchQuery>) -> Self {
        self.search = search;
        self
    }

    /// When `false` (e.g. a modal dialog is open), the terminal won't take focus
    /// or accept keyboard/mouse input, so keystrokes can't leak to the session.
    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    pub fn show(self, ui: &mut Ui) -> Response {
        let Self { terminal: t, font, interactive, search } = self;
        t.process(ui.ctx());

        let rect = ui.available_rect_before_wrap();
        let id = Id::new(("wazowski-terminal", t.id()));
        let sense = if interactive { Sense::click_and_drag() } else { Sense::hover() };
        let response = ui.interact(rect, id, sense);
        ui.advance_cursor_after_rect(rect);

        let cell = ui.fonts_mut(|f| vec2(f.glyph_width(&font, 'M'), f.row_height(&font)));
        let inner = rect.shrink(PADDING);
        let cols = ((inner.width() / cell.x).floor() as usize).max(2);
        let rows = ((inner.height() / cell.y).floor() as usize).max(1);
        t.resize(TermSize {
            cols: cols as u16,
            rows: rows as u16,
            cell_width: cell.x.round() as u16,
            cell_height: cell.y.round() as u16,
        });
        let grid = Grid { origin: inner.min, cell, cols, rows };

        // While non-interactive (a dialog is up), give up focus so input goes to
        // the dialog, not the remote session.
        if !interactive {
            if response.has_focus() {
                response.surrender_focus();
            }
            paint(ui, t, rect, &grid, &font, false, search.as_ref());
            return response;
        }

        if response.clicked() || response.drag_started() || ui.memory(|m| m.focused().is_none()) {
            response.request_focus();
        }
        let focused = response.has_focus();
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    id,
                    EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
            handle_keyboard(ui, t);
        }
        handle_mouse(ui, t, &response, &grid);
        if response.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::Text);
        }

        paint(ui, t, rect, &grid, &font, focused, search.as_ref());
        response
    }
}

fn handle_keyboard(ui: &Ui, t: &mut Terminal) {
    let (events, mods) = ui.input(|i| (i.events.clone(), i.modifiers));
    let app_cursor = t.term.mode().contains(TermMode::APP_CURSOR);

    for event in events {
        match event {
            egui::Event::Text(text) => {
                if mods.alt && !mods.ctrl {
                    t.input(format!("\x1b{text}").as_bytes());
                } else {
                    t.input(text.as_bytes());
                }
            }
            egui::Event::Ime(egui::ImeEvent::Commit(text)) => t.input(text.as_bytes()),
            egui::Event::Key { key, pressed: true, modifiers, .. } => {
                if modifiers.shift && !modifiers.ctrl {
                    match key {
                        Key::PageUp => {
                            t.term.scroll_display(Scroll::PageUp);
                            continue;
                        }
                        Key::PageDown => {
                            t.term.scroll_display(Scroll::PageDown);
                            continue;
                        }
                        _ => {}
                    }
                }
                if let Some(bytes) = key_to_bytes(key, modifiers, app_cursor) {
                    t.input(&bytes);
                }
            }
            // egui turns Ctrl+C/X/V into clipboard events. In a terminal only the
            // shifted variants (or Cmd on macOS) mean copy/paste; plain Ctrl
            // must reach the program as a control character.
            egui::Event::Copy => {
                if mods.shift || mods.mac_cmd {
                    if let Some(text) = t.selection_text() {
                        ui.ctx().copy_text(text);
                    }
                } else {
                    t.input(b"\x03");
                }
            }
            egui::Event::Cut if !mods.mac_cmd => t.input(b"\x18"),
            egui::Event::Paste(text) => {
                if t.paste_requested || mods.shift || mods.mac_cmd {
                    t.paste_requested = false;
                    t.paste(&text);
                } else {
                    t.input(b"\x16");
                }
            }
            _ => {}
        }
    }
}

fn handle_mouse(ui: &Ui, t: &mut Terminal, response: &Response, grid: &Grid) {
    let offset = t.term.grid().display_offset();

    if let Some(pos) = response.interact_pointer_pos() {
        let (point, side) = grid.point_at(pos, offset);
        let select = |t: &mut Terminal, ty| {
            let mut selection = Selection::new(ty, point, side);
            selection.update(point, side);
            t.term.selection = Some(selection);
        };

        if response.triple_clicked() {
            select(t, SelectionType::Lines);
            copy_selection(ui, t);
        } else if response.double_clicked() {
            select(t, SelectionType::Semantic);
            copy_selection(ui, t);
        } else if response.drag_started_by(PointerButton::Primary) {
            select(t, SelectionType::Simple);
        } else if response.dragged_by(PointerButton::Primary) {
            if let Some(selection) = &mut t.term.selection {
                selection.update(point, side);
            }
        } else if response.clicked_by(PointerButton::Primary) {
            t.term.selection = None;
        }

        if response.drag_stopped_by(PointerButton::Primary) {
            copy_selection(ui, t);
        }
    }

    if response.secondary_clicked() || response.middle_clicked() {
        response.request_focus();
        t.paste_requested = true;
        ui.ctx().send_viewport_cmd(ViewportCommand::RequestPaste);
    }

    if response.hovered() {
        // Ctrl+wheel zooms the font instead of scrolling; report it to the app.
        let (zoom, lines): (f32, f32) = ui.input(|i| {
            let mut zoom = 0.0;
            let mut lines = 0.0;
            for e in &i.events {
                if let egui::Event::MouseWheel { unit, delta, modifiers, .. } = e {
                    if modifiers.ctrl || modifiers.command {
                        zoom += delta.y;
                    } else {
                        lines += match unit {
                            MouseWheelUnit::Point => delta.y / grid.cell.y,
                            MouseWheelUnit::Line => delta.y * 3.0,
                            MouseWheelUnit::Page => delta.y * grid.rows as f32,
                        };
                    }
                }
            }
            (zoom, lines)
        });
        if zoom != 0.0 {
            t.add_zoom(zoom);
        }
        if lines != 0.0 {
            t.scroll_remainder += lines;
            let lines = t.scroll_remainder.trunc() as i32;
            t.scroll_remainder -= lines as f32;
            if lines != 0 {
                scroll(t, lines);
            }
        }
    }
}

/// Scrolls the history, or in full-screen programs like `less` sends arrow keys instead.
fn scroll(t: &mut Terminal, lines: i32) {
    let mode = *t.term.mode();
    if mode.contains(TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL) {
        let key = if lines > 0 { Key::ArrowUp } else { Key::ArrowDown };
        let app_cursor = mode.contains(TermMode::APP_CURSOR);
        if let Some(bytes) = key_to_bytes(key, Modifiers::NONE, app_cursor) {
            t.write(&bytes.repeat(lines.unsigned_abs() as usize));
        }
    } else {
        t.term.scroll_display(Scroll::Delta(lines));
    }
}

fn copy_selection(ui: &Ui, t: &Terminal) {
    if let Some(text) = t.selection_text() {
        ui.ctx().copy_text(text);
    }
}

/// A stretch of same-colored ASCII text on one row, drawn as a single string.
/// Anything else is drawn one cell at a time so fallback-font glyphs can't
/// push the rest of the line out of alignment.
struct TextRun {
    pos: Pos2,
    row: i32,
    next_col: usize,
    color: Color32,
    ascii: bool,
    text: String,
}

fn paint(
    ui: &Ui,
    t: &Terminal,
    rect: Rect,
    grid: &Grid,
    font: &FontId,
    focused: bool,
    search: Option<&SearchQuery>,
) {
    let painter = ui.painter_at(rect);
    let palette = &t.palette;
    painter.rect_filled(rect, 0.0, palette.background);

    // Per visible row, the (column, char) of each cell, to map find matches to
    // screen positions after the cell loop.
    let searching = search.is_some_and(|q| !q.needle.is_empty());
    let mut row_chars: Vec<Vec<(usize, char)>> = if searching {
        vec![Vec::new(); grid.rows]
    } else {
        Vec::new()
    };

    let content = t.term.renderable_content();
    let colors = content.colors;
    let offset = content.display_offset as i32;
    let cursor = content.cursor;
    let cursor_row = cursor.point.line.0 + offset;
    let cursor_col = cursor.point.column.0;
    let cursor_color = palette.resolve(Color::Named(NamedColor::Cursor), colors);
    let block_cursor = focused && cursor.shape == CursorShape::Block;

    let mut backgrounds = Vec::new();
    let mut lines = Vec::new();
    let mut runs: Vec<TextRun> = Vec::new();

    for indexed in content.display_iter {
        let cell = indexed.cell;
        let flags = cell.flags;
        if flags.contains(Flags::WIDE_CHAR_SPACER) {
            continue;
        }
        let row = indexed.point.line.0 + offset;
        let col = indexed.point.column.0;

        if searching
            && row >= 0
            && let Some(cells) = row_chars.get_mut(row as usize)
        {
            cells.push((col, cell.c));
        }

        let mut fg = foreground(cell, palette, colors);
        let mut bg = palette.resolve(cell.bg, colors);
        if flags.contains(Flags::INVERSE) {
            std::mem::swap(&mut fg, &mut bg);
        }
        if content.selection.is_some_and(|s| s.contains(indexed.point)) {
            bg = palette.selection;
        }
        if block_cursor && row == cursor_row && col == cursor_col {
            bg = cursor_color;
            fg = palette.background;
        }
        if flags.contains(Flags::HIDDEN) {
            fg = bg;
        }

        let width = if flags.contains(Flags::WIDE_CHAR) { 2 } else { 1 };
        let cell_rect = grid.cell_rect(row, col, width);
        if bg != palette.background {
            backgrounds.push((cell_rect, bg));
        }
        if flags.intersects(Flags::ALL_UNDERLINES) {
            let y = cell_rect.bottom() - 1.0;
            lines.push(([pos2(cell_rect.left(), y), pos2(cell_rect.right(), y)], fg));
        }
        if flags.contains(Flags::STRIKEOUT) {
            let y = cell_rect.center().y;
            lines.push(([pos2(cell_rect.left(), y), pos2(cell_rect.right(), y)], fg));
        }

        let zerowidth = cell.zerowidth().unwrap_or_default();
        let ascii = cell.c.is_ascii() && zerowidth.is_empty() && width == 1;
        let extends = runs.last().is_some_and(|run| {
            run.ascii && ascii && run.row == row && run.next_col == col && run.color == fg
        });
        if !extends {
            runs.push(TextRun {
                pos: cell_rect.min,
                row,
                next_col: col,
                color: fg,
                ascii,
                text: String::new(),
            });
        }
        let run = runs.last_mut().expect("a run was just pushed");
        run.text.push(cell.c);
        run.text.extend(zerowidth);
        run.next_col = col + width;
    }

    for (rect, color) in backgrounds {
        painter.rect_filled(rect, 0.0, color);
    }
    for run in runs {
        if !run.text.trim().is_empty() {
            painter.text(run.pos, Align2::LEFT_TOP, run.text, font.clone(), run.color);
        }
    }
    for (points, color) in lines {
        painter.line_segment(points, Stroke::new(1.0, color));
    }

    if let Some(query) = search.filter(|_| searching) {
        paint_search(&painter, grid, &row_chars, query);
    }

    if cursor.shape != CursorShape::Hidden && (0..grid.rows as i32).contains(&cursor_row) {
        let rect = grid.cell_rect(cursor_row, cursor_col, 1);
        match cursor.shape {
            CursorShape::Block if focused => {}
            CursorShape::Beam => {
                painter.rect_filled(Rect::from_min_size(rect.min, vec2(2.0, rect.height())), 0.0, cursor_color);
            }
            CursorShape::Underline => {
                let bar = Rect::from_min_max(rect.left_bottom() - vec2(0.0, 2.0), rect.right_bottom());
                painter.rect_filled(bar, 0.0, cursor_color);
            }
            _ => {
                painter.rect_stroke(rect, 0.0, Stroke::new(1.0, cursor_color), StrokeKind::Inside);
            }
        }
    }
}

/// Draws a highlight over every occurrence of the find query on each visible row.
fn paint_search(
    painter: &egui::Painter,
    grid: &Grid,
    row_chars: &[Vec<(usize, char)>],
    query: &SearchQuery,
) {
    let needle = if query.case_sensitive { query.needle.clone() } else { query.needle.to_lowercase() };
    for (row, cells) in row_chars.iter().enumerate() {
        let text: String = cells.iter().map(|(_, c)| *c).collect();
        let hay = if query.case_sensitive { text.clone() } else { text.to_lowercase() };
        let chars: Vec<char> = hay.chars().collect();
        let needle_chars: Vec<char> = needle.chars().collect();
        // Skip rows where lowercasing changed the char count (column mapping
        // would be off); matching stays correct for the common ASCII case.
        if needle_chars.is_empty() || chars.len() != cells.len() || chars.len() < needle_chars.len()
        {
            continue;
        }
        let mut i = 0;
        while i + needle_chars.len() <= chars.len() {
            if chars[i..i + needle_chars.len()] == needle_chars[..] {
                let start_col = cells[i].0;
                let end_col = cells[i + needle_chars.len() - 1].0;
                let rect = grid.cell_rect(row as i32, start_col, end_col - start_col + 1);
                painter.rect_filled(rect, 2.0, SEARCH_HIGHLIGHT);
                i += needle_chars.len();
            } else {
                i += 1;
            }
        }
    }
}

/// Foreground color of a cell, applying the xterm "bold is bright" convention and dimming.
fn foreground(cell: &Cell, palette: &Palette, colors: &Colors) -> Color32 {
    let bold = cell.flags.contains(Flags::BOLD);
    let color = match cell.fg {
        Color::Named(name) if bold && (name as usize) < 8 => Color::Indexed(name as u8 + 8),
        Color::Indexed(i) if bold && i < 8 => Color::Indexed(i + 8),
        other => other,
    };
    let fg = palette.resolve(color, colors);
    if cell.flags.contains(Flags::DIM) { dim(fg) } else { fg }
}
