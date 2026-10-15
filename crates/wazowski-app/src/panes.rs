//! A tab's terminals arranged as a recursively splittable layout tree.
//!
//! A [`Pane`] is either a single terminal (a leaf) or a split of two child
//! panes, side by side or stacked, with a draggable divider. A leaf's terminal
//! is normally owned by this tab, but a split pane can instead *host* a session
//! moved in from another tab (its [`Home`] records where to send it back). When
//! a tab is split, each pane shows a title bar whose menu swaps which session it
//! displays.

use eframe::egui::{
    self, Color32, CursorIcon, Id, Rect, RichText, Sense, Stroke, Ui, UiBuilder, pos2, vec2,
};
use wazowski_term::{SearchQuery, Terminal, TerminalView};

/// Which way a split arranges its two children.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SplitDir {
    /// Children sit side by side, divider vertical.
    Horizontal,
    /// Children are stacked, divider horizontal.
    Vertical,
}

/// Where a moved-in session came from, so it can be returned.
#[derive(Clone)]
pub struct Home {
    pub tab_id: u64,
    pub label: String,
}

/// One terminal in the layout, with optional "moved in from another tab" origin.
pub struct Leaf {
    term: Box<Terminal>,
    home: Option<Home>,
}

/// A leaf's contents removed from the tree: its terminal and (if moved-in) home.
pub type LeafContents = (Box<Terminal>, Option<Home>);

/// A session that can be moved into a pane (another single-terminal tab).
#[derive(Clone)]
pub struct SwapTarget {
    pub tab_id: u64,
    pub label: String,
}

/// A title-bar request from a split pane, handled by the app.
pub enum PaneAction {
    /// Replace this leaf's terminal with a fresh local shell.
    NewShell(u64),
    /// Move the session from `from_tab` into this leaf.
    Swap { leaf: u64, from_tab: u64 },
    /// Return this leaf's moved-in session to its home tab (collapsing the pane).
    Return(u64),
    /// Close this pane (collapsing the split); a moved-in session returns home.
    ClosePane(u64),
    /// Close every other pane, keeping only this one.
    CloseOthers(u64),
}

/// One node of a tab's layout tree.
pub enum Pane {
    Leaf(Leaf),
    Split { dir: SplitDir, ratio: f32, a: Box<Pane>, b: Box<Pane> },
}

/// Combines two optional children back into a node, collapsing when one is gone.
fn merge(a: Option<Pane>, b: Option<Pane>, dir: SplitDir, ratio: f32) -> Option<Pane> {
    match (a, b) {
        (None, None) => None,
        (None, Some(x)) | (Some(x), None) => Some(x),
        (Some(a), Some(b)) => Some(Pane::Split { dir, ratio, a: Box::new(a), b: Box::new(b) }),
    }
}

impl Pane {
    fn leaf(term: Box<Terminal>) -> Pane {
        Pane::Leaf(Leaf { term, home: None })
    }

    fn count(&self) -> usize {
        match self {
            Pane::Leaf(_) => 1,
            Pane::Split { a, b, .. } => a.count() + b.count(),
        }
    }

    fn all_exited(&self) -> bool {
        match self {
            Pane::Leaf(l) => l.term.has_exited(),
            Pane::Split { a, b, .. } => a.all_exited() && b.all_exited(),
        }
    }

    fn first_leaf_id(&self) -> Option<u64> {
        match self {
            Pane::Leaf(l) => Some(l.term.id()),
            Pane::Split { a, .. } => a.first_leaf_id(),
        }
    }

    fn contains(&self, id: u64) -> bool {
        match self {
            Pane::Leaf(l) => l.term.id() == id,
            Pane::Split { a, b, .. } => a.contains(id) || b.contains(id),
        }
    }

    fn for_each(&mut self, f: &mut impl FnMut(&mut Terminal)) {
        match self {
            Pane::Leaf(l) => f(&mut l.term),
            Pane::Split { a, b, .. } => {
                a.for_each(f);
                b.for_each(f);
            }
        }
    }

    fn get(&self, id: u64) -> Option<&Terminal> {
        match self {
            Pane::Leaf(l) => (l.term.id() == id).then_some(l.term.as_ref()),
            Pane::Split { a, b, .. } => a.get(id).or_else(|| b.get(id)),
        }
    }

    fn get_mut(&mut self, id: u64) -> Option<&mut Terminal> {
        match self {
            Pane::Leaf(l) if l.term.id() == id => Some(l.term.as_mut()),
            Pane::Leaf(_) => None,
            Pane::Split { a, b, .. } => a.get_mut(id).or_else(|| b.get_mut(id)),
        }
    }

    fn collect_ids(&self, out: &mut Vec<u64>) {
        match self {
            Pane::Leaf(l) => out.push(l.term.id()),
            Pane::Split { a, b, .. } => {
                a.collect_ids(out);
                b.collect_ids(out);
            }
        }
    }

    fn collect_moved_ids(&self, out: &mut Vec<u64>) {
        match self {
            Pane::Leaf(l) if l.home.is_some() => out.push(l.term.id()),
            Pane::Leaf(_) => {}
            Pane::Split { a, b, .. } => {
                a.collect_moved_ids(out);
                b.collect_moved_ids(out);
            }
        }
    }

    fn collect_exited_moved(&self, out: &mut Vec<u64>) {
        match self {
            Pane::Leaf(l) if l.home.is_some() && l.term.has_exited() => out.push(l.term.id()),
            Pane::Leaf(_) => {}
            Pane::Split { a, b, .. } => {
                a.collect_exited_moved(out);
                b.collect_exited_moved(out);
            }
        }
    }

    fn clear_home(&mut self, home_tab_id: u64) {
        match self {
            Pane::Leaf(l) => {
                if l.home.as_ref().is_some_and(|h| h.tab_id == home_tab_id) {
                    l.home = None;
                }
            }
            Pane::Split { a, b, .. } => {
                a.clear_home(home_tab_id);
                b.clear_home(home_tab_id);
            }
        }
    }

    fn find_moved(&self, home_tab_id: u64) -> Option<u64> {
        match self {
            Pane::Leaf(l) if l.home.as_ref().is_some_and(|h| h.tab_id == home_tab_id) => {
                Some(l.term.id())
            }
            Pane::Leaf(_) => None,
            Pane::Split { a, b, .. } => a.find_moved(home_tab_id).or_else(|| b.find_moved(home_tab_id)),
        }
    }

    fn split_leaf(self, target: u64, dir: SplitDir, new: Pane) -> (Pane, Option<Pane>) {
        match self {
            Pane::Leaf(l) if l.term.id() == target => (
                Pane::Split { dir, ratio: 0.5, a: Box::new(Pane::Leaf(l)), b: Box::new(new) },
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

    /// Removes the leaf with `id`, returning (remaining tree, its contents).
    fn remove(self, id: u64) -> (Option<Pane>, Option<LeafContents>) {
        match self {
            Pane::Leaf(l) if l.term.id() == id => (None, Some((l.term, l.home))),
            leaf @ Pane::Leaf(_) => (Some(leaf), None),
            Pane::Split { dir, ratio, a, b } => {
                let (a2, taken) = a.remove(id);
                if taken.is_some() {
                    return (merge(a2, Some(*b), dir, ratio), taken);
                }
                let (b2, taken) = b.remove(id);
                (merge(a2, b2, dir, ratio), taken)
            }
        }
    }

    /// Drops exited owned leaves; keeps moved-in ones so their home isn't orphaned.
    fn prune(self) -> Option<Pane> {
        match self {
            Pane::Leaf(l) => {
                if l.term.has_exited() && l.home.is_none() {
                    None
                } else {
                    Some(Pane::Leaf(l))
                }
            }
            Pane::Split { dir, ratio, a, b } => merge(a.prune(), b.prune(), dir, ratio),
        }
    }

    /// Swaps a leaf's terminal/home in place, returning the old contents.
    fn replace(
        &mut self,
        id: u64,
        new: &mut Option<LeafContents>,
    ) -> Option<LeafContents> {
        match self {
            Pane::Leaf(l) if l.term.id() == id && new.is_some() => {
                let (nt, nh) = new.take().unwrap();
                let old_term = std::mem::replace(&mut l.term, nt);
                let old_home = std::mem::replace(&mut l.home, nh);
                Some((old_term, old_home))
            }
            Pane::Leaf(_) => None,
            Pane::Split { a, b, .. } => {
                let r = a.replace(id, new);
                if r.is_some() { r } else { b.replace(id, new) }
            }
        }
    }

    fn single_term(self) -> Option<Box<Terminal>> {
        match self {
            Pane::Leaf(l) => Some(l.term),
            Pane::Split { .. } => None,
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
        Self { root: Some(Pane::leaf(term)), focused }
    }

    pub fn count(&self) -> usize {
        self.root.as_ref().map_or(0, Pane::count)
    }

    pub fn focused_id(&self) -> u64 {
        self.focused
    }

    pub fn all_exited(&self) -> bool {
        self.root.as_ref().is_none_or(Pane::all_exited)
    }

    pub fn ids(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            root.collect_ids(&mut out);
        }
        out
    }

    pub fn get(&self, id: u64) -> Option<&Terminal> {
        self.root.as_ref().and_then(|r| r.get(id))
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Terminal> {
        self.root.as_mut().and_then(|r| r.get_mut(id))
    }

    pub fn for_each(&mut self, mut f: impl FnMut(&mut Terminal)) {
        if let Some(root) = &mut self.root {
            root.for_each(&mut f);
        }
    }

    pub fn split(&mut self, dir: SplitDir, term: Box<Terminal>) {
        let Some(root) = self.root.take() else { return };
        let new_id = term.id();
        let (root, _) = root.split_leaf(self.focused, dir, Pane::leaf(term));
        self.root = Some(root);
        self.focused = new_id;
    }

    /// Closes the focused pane (unless it's the only one), returning its contents
    /// so the caller can send a moved-in session home.
    pub fn close_focused(&mut self) -> Option<LeafContents> {
        if self.count() <= 1 {
            return None;
        }
        let root = self.root.take()?;
        let (root, taken) = root.remove(self.focused);
        self.root = root;
        self.focused = self.root.as_ref().and_then(Pane::first_leaf_id).unwrap_or(self.focused);
        taken
    }

    /// Removes a specific leaf by terminal id, returning its contents.
    pub fn remove_leaf(&mut self, id: u64) -> Option<LeafContents> {
        let root = self.root.take()?;
        let (root, taken) = root.remove(id);
        self.root = root;
        if !self.root.as_ref().is_some_and(|r| r.contains(self.focused)) {
            self.focused = self.root.as_ref().and_then(Pane::first_leaf_id).unwrap_or(self.focused);
        }
        taken
    }

    /// Replaces a leaf's terminal (and home), returning the old contents.
    pub fn replace_leaf(
        &mut self,
        id: u64,
        term: Box<Terminal>,
        home: Option<Home>,
    ) -> Option<LeafContents> {
        let new_id = term.id();
        let mut slot = Some((term, home));
        let old = self.root.as_mut().and_then(|r| r.replace(id, &mut slot));
        if old.is_some() && self.focused == id {
            self.focused = new_id;
        }
        old
    }

    /// Extracts the terminal if this tab holds exactly one (owned) leaf.
    pub fn take_single(&mut self) -> Option<Box<Terminal>> {
        if self.count() != 1 {
            return None;
        }
        self.root.take().and_then(Pane::single_term)
    }

    /// Removes every leaf except the one with `keep`, returning their contents.
    pub fn keep_only(&mut self, keep: u64) -> Vec<LeafContents> {
        let others: Vec<u64> = self.ids().into_iter().filter(|id| *id != keep).collect();
        others.into_iter().filter_map(|id| self.remove_leaf(id)).collect()
    }

    /// Removes every moved-in leaf, returning each with its home (e.g. on close).
    pub fn drain_moved(&mut self) -> Vec<(Box<Terminal>, Home)> {
        let mut ids = Vec::new();
        if let Some(root) = &self.root {
            root.collect_moved_ids(&mut ids);
        }
        let mut out = Vec::new();
        for id in ids {
            if let Some((term, Some(home))) = self.remove_leaf(id) {
                out.push((term, home));
            }
        }
        out
    }

    /// Converts a leaf hosting `home_tab_id`'s session into an owned leaf (used
    /// when that home tab is closed, so the session isn't orphaned).
    pub fn clear_home(&mut self, home_tab_id: u64) {
        if let Some(root) = &mut self.root {
            root.clear_home(home_tab_id);
        }
    }

    /// The terminal id of the leaf currently hosting `home_tab_id`'s session.
    pub fn moved_from(&self, home_tab_id: u64) -> Option<u64> {
        self.root.as_ref().and_then(|r| r.find_moved(home_tab_id))
    }

    /// Terminal ids of moved-in leaves whose session has exited.
    pub fn exited_moved(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            root.collect_exited_moved(&mut out);
        }
        out
    }

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

    /// Renders the tree. Returns the id and bytes typed into the focused pane
    /// this frame (for broadcast); title-bar requests go to `action`.
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        ui: &mut Ui,
        interactive: bool,
        broadcast_active: bool,
        search: Option<&SearchQuery>,
        targets: &[SwapTarget],
        origin: Option<u64>,
        action: &mut Option<PaneAction>,
    ) -> Option<(u64, Vec<u8>)> {
        let area = ui.available_rect_before_wrap();
        let multi = self.count() > 1;
        let focused = self.focused;
        let mut new_focus = self.focused;
        let mut source = None;
        if let Some(root) = &mut self.root {
            show_pane(
                Ctx {
                    interactive,
                    broadcast_active,
                    multi,
                    focused,
                    search,
                    targets,
                    origin,
                    new_focus: &mut new_focus,
                    source: &mut source,
                    action,
                },
                ui,
                root,
                area,
            );
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
    search: Option<&'a SearchQuery>,
    targets: &'a [SwapTarget],
    /// The tab's original session terminal id (CloseOthers is offered only there).
    origin: Option<u64>,
    new_focus: &'a mut u64,
    source: &'a mut Option<(u64, Vec<u8>)>,
    action: &'a mut Option<PaneAction>,
}

impl Ctx<'_> {
    fn reborrow(&mut self) -> Ctx<'_> {
        Ctx {
            interactive: self.interactive,
            broadcast_active: self.broadcast_active,
            multi: self.multi,
            focused: self.focused,
            search: self.search,
            targets: self.targets,
            origin: self.origin,
            new_focus: self.new_focus,
            source: self.source,
            action: self.action,
        }
    }
}

const TITLE_H: f32 = 22.0;

fn show_pane(mut cx: Ctx, ui: &mut Ui, pane: &mut Pane, area: Rect) {
    match pane {
        Pane::Leaf(leaf) => {
            let id = leaf.term.id();
            // Split panes get a title bar strip above the terminal.
            let (bar, term_rect) = if cx.multi {
                (
                    Some(Rect::from_min_size(area.min, vec2(area.width(), TITLE_H))),
                    Rect::from_min_max(pos2(area.min.x, area.min.y + TITLE_H), area.max),
                )
            } else {
                (None, area)
            };

            let response = ui
                .scope_builder(UiBuilder::new().max_rect(term_rect), |ui| {
                    TerminalView::new(&mut leaf.term)
                        .interactive(cx.interactive)
                        .search(cx.search.cloned())
                        .show(ui)
                })
                .inner;

            let typed = leaf.term.take_broadcast();
            if !typed.is_empty() {
                *cx.source = Some((id, typed));
            }
            if response.has_focus() || response.clicked() || response.drag_started() {
                *cx.new_focus = id;
            }

            if let Some(bar) = bar {
                title_bar(&mut cx, ui, bar, leaf, id);
            }
            if cx.broadcast_active {
                exclude_toggle(ui, &mut leaf.term, bar.unwrap_or(area));
            }
            if cx.multi && id == cx.focused {
                let stroke = Stroke::new(1.5, ui.visuals().selection.stroke.color);
                ui.painter().rect_stroke(term_rect.shrink(1.0), 2.0, stroke, egui::StrokeKind::Inside);
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

/// A split pane's title bar: current session plus a menu to swap what it shows.
fn title_bar(cx: &mut Ctx, ui: &mut Ui, bar: Rect, leaf: &Leaf, id: u64) {
    ui.painter().rect_filled(bar, 0.0, ui.visuals().faint_bg_color);
    let moved = leaf.home.is_some();
    let label = match &leaf.home {
        Some(home) => format!("⇄ {}", home.label),
        None => {
            let title = leaf.term.title();
            if title.is_empty() { "Shell".to_owned() } else { title.to_owned() }
        }
    };
    ui.scope_builder(UiBuilder::new().max_rect(bar.shrink2(vec2(4.0, 2.0))), |ui| {
        ui.horizontal_centered(|ui| {
            ui.menu_button("▾", |ui| {
                // The tab's original-session pane only offers collapsing the others.
                if cx.origin == Some(id) {
                    if ui.button("Close other panes").clicked() {
                        *cx.action = Some(PaneAction::CloseOthers(id));
                        ui.close();
                    }
                    return;
                }
                if ui.button("New shell here").clicked() {
                    *cx.action = Some(PaneAction::NewShell(id));
                    ui.close();
                }
                if moved && ui.button("Return to its tab").clicked() {
                    *cx.action = Some(PaneAction::Return(id));
                    ui.close();
                }
                if ui.button("Close this pane").clicked() {
                    *cx.action = Some(PaneAction::ClosePane(id));
                    ui.close();
                }
                // Collapse back to just the tab's original session.
                if let Some(origin) = cx.origin
                    && ui.button("Close all but original session").clicked()
                {
                    *cx.action = Some(PaneAction::CloseOthers(origin));
                    ui.close();
                }
                if !cx.targets.is_empty() {
                    ui.separator();
                    ui.label(RichText::new("Show session").weak());
                    for target in cx.targets {
                        if ui.button(&target.label).clicked() {
                            *cx.action = Some(PaneAction::Swap { leaf: id, from_tab: target.tab_id });
                            ui.close();
                        }
                    }
                }
            });
            ui.label(RichText::new(label).small());
        });
    });
}

/// A small corner button to drop a pane in or out of broadcast.
fn exclude_toggle(ui: &mut Ui, t: &mut Terminal, area: Rect) {
    let size = vec2(24.0, 18.0);
    let rect = Rect::from_min_size(pos2(area.max.x - size.x - 4.0, area.min.y + 2.0), size);
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
