//! A tab's terminals arranged as a recursively splittable layout tree.
//!
//! A [`Pane`] is either a single terminal (a leaf) or a split of two child
//! panes, side by side or stacked, with a draggable divider. [`Panes`] wraps the
//! root and tracks which leaf currently has focus — new splits land there, and
//! that leaf is the source for multi-exec broadcast.

use eframe::egui::{
    self, Color32, CursorIcon, Id, Rect, RichText, Sense, Stroke, Ui, UiBuilder, pos2, vec2,
};
use wazowski_term::{Terminal, TerminalView};

/// Which way a split arranges its two children.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SplitDir {
    /// Children sit side by side, divider vertical.
    Horizontal,
    /// Children are stacked, divider horizontal.
    Vertical,
}

/// One node of a tab's layout tree.
pub enum Pane {
    Leaf(Box<Terminal>),
    Split { dir: SplitDir, ratio: f32, a: Box<Pane>, b: Box<Pane> },
}

impl Pane {
    fn count(&self) -> usize {
        match self {
            Pane::Leaf(_) => 1,
            Pane::Split { a, b, .. } => a.count() + b.count(),
        }
    }

    fn all_exited(&self) -> bool {
        match self {
            Pane::Leaf(t) => t.has_exited(),
            Pane::Split { a, b, .. } => a.all_exited() && b.all_exited(),
        }
    }

    fn first_leaf_id(&self) -> Option<u64> {
        match self {
            Pane::Leaf(t) => Some(t.id()),
            Pane::Split { a, .. } => a.first_leaf_id(),
        }
    }

    fn contains(&self, id: u64) -> bool {
        match self {
            Pane::Leaf(t) => t.id() == id,
            Pane::Split { a, b, .. } => a.contains(id) || b.contains(id),
        }
    }

    fn for_each(&mut self, f: &mut impl FnMut(&mut Terminal)) {
        match self {
            Pane::Leaf(t) => f(t),
            Pane::Split { a, b, .. } => {
                a.for_each(f);
                b.for_each(f);
            }
        }
    }

    /// Replaces the leaf with id `target` by a split of it and `new`. Returns
    /// `new` unconsumed if the target was not found in this subtree.
    fn split_leaf(self, target: u64, dir: SplitDir, new: Pane) -> (Pane, Option<Pane>) {
        match self {
            Pane::Leaf(t) if t.id() == target => (
                Pane::Split { dir, ratio: 0.5, a: Box::new(Pane::Leaf(t)), b: Box::new(new) },
                None,
            ),
            leaf @ Pane::Leaf(_) => (leaf, Some(new)),
            Pane::Split { dir: d, ratio, a, b } => {
                let (a, leftover) = a.split_leaf(target, dir, new);
                match leftover {
                    None => (Pane::Split { dir: d, ratio, a: Box::new(a), b }, None),
                    Some(new) => {
                        let (b, leftover) = b.split_leaf(target, dir, new);
                        (Pane::Split { dir: d, ratio, a: Box::new(a), b: Box::new(b) }, leftover)
                    }
                }
            }
        }
    }

    /// Removes the leaf with id `target`, collapsing a split that loses a child.
    /// Returns `None` if the whole subtree is gone.
    fn close_leaf(self, target: u64) -> Option<Pane> {
        match self {
            Pane::Leaf(t) if t.id() == target => None,
            leaf @ Pane::Leaf(_) => Some(leaf),
            Pane::Split { dir, ratio, a, b } => {
                match (a.close_leaf(target), b.close_leaf(target)) {
                    (None, None) => None,
                    (None, Some(x)) | (Some(x), None) => Some(x),
                    (Some(a), Some(b)) => {
                        Some(Pane::Split { dir, ratio, a: Box::new(a), b: Box::new(b) })
                    }
                }
            }
        }
    }

    /// Drops leaves whose terminal has exited, collapsing splits that empty out.
    fn prune(self) -> Option<Pane> {
        match self {
            Pane::Leaf(t) if t.has_exited() => None,
            leaf @ Pane::Leaf(_) => Some(leaf),
            Pane::Split { dir, ratio, a, b } => match (a.prune(), b.prune()) {
                (None, None) => None,
                (None, Some(x)) | (Some(x), None) => Some(x),
                (Some(a), Some(b)) => {
                    Some(Pane::Split { dir, ratio, a: Box::new(a), b: Box::new(b) })
                }
            },
        }
    }
}

/// A tab's terminals and which leaf has focus. `root` is `Some` while the tab is
/// alive; it becomes `None` only once every pane has exited.
pub struct Panes {
    root: Option<Pane>,
    focused: u64,
}

impl Panes {
    pub fn new(term: Box<Terminal>) -> Self {
        let focused = term.id();
        Self { root: Some(Pane::Leaf(term)), focused }
    }

    pub fn count(&self) -> usize {
        self.root.as_ref().map_or(0, Pane::count)
    }

    /// Whether every pane's terminal has ended (so the tab can be dropped).
    pub fn all_exited(&self) -> bool {
        self.root.as_ref().is_none_or(Pane::all_exited)
    }

    /// Runs `f` over every terminal in the tree.
    pub fn for_each(&mut self, mut f: impl FnMut(&mut Terminal)) {
        if let Some(root) = &mut self.root {
            root.for_each(&mut f);
        }
    }

    /// Splits the focused pane, placing `term` beside it and focusing the newcomer.
    pub fn split(&mut self, dir: SplitDir, term: Box<Terminal>) {
        let Some(root) = self.root.take() else { return };
        let new_id = term.id();
        let (root, _) = root.split_leaf(self.focused, dir, Pane::Leaf(term));
        self.root = Some(root);
        self.focused = new_id;
    }

    /// Closes the focused pane, unless it is the only one left.
    pub fn close_focused(&mut self) {
        if self.count() <= 1 {
            return;
        }
        let Some(root) = self.root.take() else { return };
        self.root = root.close_leaf(self.focused);
        self.focused = self.root.as_ref().and_then(Pane::first_leaf_id).unwrap_or(self.focused);
    }

    /// Drops panes whose shell exited; focus moves to a survivor if it had to.
    pub fn prune(&mut self) {
        let Some(root) = self.root.take() else { return };
        self.root = root.prune();
        if let Some(root) = &self.root
            && !root.contains(self.focused)
            && let Some(id) = root.first_leaf_id()
        {
            self.focused = id;
        }
    }

    /// Renders the tree, updating focus. Returns the id and bytes typed into the
    /// focused pane this frame, for multi-exec broadcast (the caller mirrors them
    /// to the other, non-excluded terminals).
    pub fn show(
        &mut self,
        ui: &mut Ui,
        interactive: bool,
        broadcast_active: bool,
    ) -> Option<(u64, Vec<u8>)> {
        let area = ui.available_rect_before_wrap();
        let multi = self.count() > 1;
        let focused = self.focused;
        let mut new_focus = self.focused;
        let mut source = None;
        if let Some(root) = &mut self.root {
            show_pane(Ctx {
                interactive,
                broadcast_active,
                multi,
                focused,
                new_focus: &mut new_focus,
                source: &mut source,
            }, ui, root, area);
        }
        self.focused = new_focus;
        source
    }
}

/// Shared state threaded through the recursive render.
struct Ctx<'a> {
    interactive: bool,
    broadcast_active: bool,
    multi: bool,
    focused: u64,
    new_focus: &'a mut u64,
    source: &'a mut Option<(u64, Vec<u8>)>,
}

fn show_pane(mut cx: Ctx, ui: &mut Ui, pane: &mut Pane, area: Rect) {
    match pane {
        Pane::Leaf(t) => {
            let id = t.id();
            let response = ui
                .scope_builder(UiBuilder::new().max_rect(area), |ui| {
                    TerminalView::new(t).interactive(cx.interactive).show(ui)
                })
                .inner;

            // Always drain so input never piles up while broadcast is off.
            let typed = t.take_broadcast();
            if !typed.is_empty() {
                *cx.source = Some((id, typed));
            }
            if response.has_focus() || response.clicked() || response.drag_started() {
                *cx.new_focus = id;
            }

            if cx.broadcast_active {
                exclude_toggle(ui, t, area);
            }
            if cx.multi && id == cx.focused {
                let stroke = Stroke::new(1.5, ui.visuals().selection.stroke.color);
                ui.painter().rect_stroke(
                    area.shrink(1.0),
                    2.0,
                    stroke,
                    egui::StrokeKind::Inside,
                );
            }
        }
        Pane::Split { dir, ratio, a, b } => {
            let dir = *dir;
            let gap = 6.0;
            let (ra, rb, divider) = split_rects(area, dir, *ratio, gap);

            show_pane(cx.reborrow(), ui, a, ra);

            let did = Id::new(("wz-divider", a.first_leaf_id(), b.first_leaf_id()));
            let dresp = ui.interact(divider, did, Sense::drag());
            let icon = match dir {
                SplitDir::Horizontal => CursorIcon::ResizeHorizontal,
                SplitDir::Vertical => CursorIcon::ResizeVertical,
            };
            if dresp.hovered() || dresp.dragged() {
                ui.ctx().set_cursor_icon(icon);
            }
            if dresp.dragged() {
                let delta = dresp.drag_delta();
                let (moved, total) = match dir {
                    SplitDir::Horizontal => (delta.x, area.width()),
                    SplitDir::Vertical => (delta.y, area.height()),
                };
                if total > 0.0 {
                    *ratio = (*ratio + moved / total).clamp(0.08, 0.92);
                }
            }
            let color = if dresp.hovered() || dresp.dragged() {
                ui.visuals().selection.stroke.color
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke.color
            };
            ui.painter().rect_filled(divider, 0.0, color);

            show_pane(cx.reborrow(), ui, b, rb);
        }
    }
}

impl Ctx<'_> {
    /// A shorter-lived view of the same state, for recursive calls.
    fn reborrow(&mut self) -> Ctx<'_> {
        Ctx {
            interactive: self.interactive,
            broadcast_active: self.broadcast_active,
            multi: self.multi,
            focused: self.focused,
            new_focus: self.new_focus,
            source: self.source,
        }
    }
}

/// A small corner button to drop a pane in or out of broadcast.
fn exclude_toggle(ui: &mut Ui, t: &mut Terminal, area: Rect) {
    let size = vec2(24.0, 20.0);
    let rect = Rect::from_min_size(pos2(area.max.x - size.x - 4.0, area.min.y + 4.0), size);
    let excluded = t.broadcast_excluded();
    let text = if excluded {
        RichText::new("⇉").strikethrough().color(Color32::GRAY)
    } else {
        RichText::new("⇉").color(ui.visuals().selection.stroke.color)
    };
    let hover = if excluded {
        "Excluded from broadcast — click to include"
    } else {
        "In broadcast — click to exclude this terminal"
    };
    if ui.put(rect, egui::Button::new(text).small()).on_hover_text(hover).clicked() {
        t.set_broadcast_excluded(!excluded);
    }
}

/// Splits `area` into the two child rects and the divider rect between them.
fn split_rects(area: Rect, dir: SplitDir, ratio: f32, gap: f32) -> (Rect, Rect, Rect) {
    match dir {
        SplitDir::Horizontal => {
            let usable = (area.width() - gap).max(0.0);
            let aw = usable * ratio;
            let a = Rect::from_min_size(area.min, vec2(aw, area.height()));
            let divider =
                Rect::from_min_size(pos2(area.min.x + aw, area.min.y), vec2(gap, area.height()));
            let b = Rect::from_min_max(pos2(area.min.x + aw + gap, area.min.y), area.max);
            (a, b, divider)
        }
        SplitDir::Vertical => {
            let usable = (area.height() - gap).max(0.0);
            let ah = usable * ratio;
            let a = Rect::from_min_size(area.min, vec2(area.width(), ah));
            let divider =
                Rect::from_min_size(pos2(area.min.x, area.min.y + ah), vec2(area.width(), gap));
            let b = Rect::from_min_max(pos2(area.min.x, area.min.y + ah + gap), area.max);
            (a, b, divider)
        }
    }
}
