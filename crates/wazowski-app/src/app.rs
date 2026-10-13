//! The Wazowski application: tabs, the session-manager sidebar, the encrypted
//! vault, and the dialogs that tie them together.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eframe::egui::{self, Color32, Key, KeyboardShortcut, Modifiers, RichText};
use wazowski_core::session::Auth;
use wazowski_core::{Secret, Session, SessionStore, Vault, VaultError};
use wazowski_ssh::{
    AuthMaterial, ConnectParams, HostKeyPolicy, UnknownHostKey, trust_host,
};
use wazowski_term::{LocalPty, TermSize, Terminal, TerminalView};

use crate::connect::{Connected, PendingConnect, Progress};

const NEW_TAB: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::T);
const CLOSE_TAB: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::W);
const NEXT_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::PageDown);
const PREV_TAB: KeyboardShortcut = KeyboardShortcut::new(Modifiers::CTRL, Key::PageUp);

/// An open terminal tab.
struct Tab {
    terminal: Terminal,
    /// Label shown on the tab; a session name or "Shell".
    label: String,
}

/// Where the encrypted vault stands this session.
enum VaultState {
    /// No vault file exists yet.
    Absent,
    /// A vault file exists but has not been unlocked.
    Locked,
    /// The vault is open for this session.
    Unlocked(Box<Vault>),
}

impl VaultState {
    fn unlocked(&self) -> Option<&Vault> {
        match self {
            VaultState::Unlocked(v) => Some(v),
            _ => None,
        }
    }

    fn unlocked_mut(&mut self) -> Option<&mut Vault> {
        match self {
            VaultState::Unlocked(v) => Some(v),
            _ => None,
        }
    }
}

/// A modal dialog, at most one at a time.
enum Dialog {
    None,
    UnlockVault { password: String, error: Option<String> },
    CreateVault { password: String, confirm: String, error: Option<String> },
    EditSession(SessionForm),
    HostKey { info: UnknownHostKey, changed: bool, title: String, params: ConnectParams },
    QuickConnect(ConnectAuthForm),
    VaultManager(VaultManagerState),
}

/// How a quick connection should authenticate.
#[derive(PartialEq, Eq, Clone, Copy)]
enum ConnectAuth {
    Agent,
    Password,
    VaultSecret,
}

/// State of the quick-connect auth chooser.
struct ConnectAuthForm {
    session: Session,
    method: ConnectAuth,
    password: String,
    /// Selected vault entry name, when using `VaultSecret`.
    secret_name: Option<String>,
    error: Option<String>,
}

impl ConnectAuthForm {
    fn new(session: Session) -> Self {
        Self {
            session,
            method: ConnectAuth::Agent,
            password: String::new(),
            secret_name: None,
            error: None,
        }
    }
}

/// State of the vault manager dialog.
#[derive(Default)]
struct VaultManagerState {
    /// An open add/edit form, if any.
    form: Option<SecretForm>,
    error: Option<String>,
}

/// Fields for adding or editing one vault entry.
struct SecretForm {
    /// Name of the entry being edited, or `None` when adding.
    original: Option<String>,
    name: String,
    kind: SecretKind,
    value: String,
    passphrase: String,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SecretKind {
    Password,
    Key,
}

impl SecretForm {
    fn new() -> Self {
        Self {
            original: None,
            name: String::new(),
            kind: SecretKind::Password,
            value: String::new(),
            passphrase: String::new(),
        }
    }
}

/// Editable fields for the new/edit-session dialog.
struct SessionForm {
    /// Id of the session being edited, or `None` when creating.
    id: Option<String>,
    name: String,
    folder: String,
    host: String,
    port: String,
    username: String,
    method: AuthMethod,
    /// Secret entered for password/key methods (blank keeps the existing one when editing).
    secret_input: String,
    key_passphrase: String,
    legacy: bool,
    error: Option<String>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMethod {
    Agent,
    Password,
    Key,
}

pub struct App {
    tabs: Vec<Tab>,
    active: usize,
    error: Option<String>,
    sessions: SessionStore,
    vault: VaultState,
    vault_path: PathBuf,
    dialog: Dialog,
    quick_connect: String,
    pending: Vec<PendingConnect>,
}

impl App {
    pub fn new(ctx: &egui::Context) -> Self {
        let sessions_path = SessionStore::default_path().unwrap_or_else(|_| "sessions.toml".into());
        let sessions = SessionStore::load(sessions_path).unwrap_or_default();
        let vault_path = Vault::default_path().unwrap_or_else(|_| "vault.enc".into());
        let vault = initial_vault_state(&vault_path);

        let mut app = Self {
            tabs: Vec::new(),
            active: 0,
            error: None,
            sessions,
            vault,
            vault_path,
            dialog: Dialog::None,
            quick_connect: String::new(),
            pending: Vec::new(),
        };
        app.open_local_shell(ctx);
        app
    }

    // --- Tabs ---------------------------------------------------------------

    fn open_local_shell(&mut self, ctx: &egui::Context) {
        let size = TermSize::default();
        let ctx = ctx.clone();
        match LocalPty::spawn(size, move || ctx.request_repaint()) {
            Ok((pty, output)) => self.push_tab(Terminal::new(Box::new(pty), output, size), "Shell"),
            Err(e) => self.error = Some(format!("Could not start a shell: {e:#}")),
        }
    }

    fn push_tab(&mut self, terminal: Terminal, label: impl Into<String>) {
        self.tabs.push(Tab { terminal, label: label.into() });
        self.active = self.tabs.len() - 1;
    }

    fn close_tab(&mut self, index: usize) {
        if index < self.tabs.len() {
            self.tabs.remove(index);
        }
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len().saturating_sub(1);
        }
    }

    // --- Connecting ---------------------------------------------------------

    /// Starts connecting to `session`, resolving its credentials from the vault.
    fn start_connect(&mut self, session: &Session, ctx: &egui::Context) {
        let auth = match self.resolve_auth(&session.auth) {
            Ok(auth) => auth,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.connect_with(&session.name, session, auth, ctx);
    }

    /// Spawns a connection to `session` with already-resolved credentials.
    fn connect_with(
        &mut self,
        title: &str,
        session: &Session,
        auth: AuthMaterial,
        ctx: &egui::Context,
    ) {
        let params = ConnectParams {
            host: session.host.clone(),
            port: session.port,
            username: session.username.clone(),
            auth,
            policy: HostKeyPolicy::Strict,
            size: TermSize::default(),
            known_hosts: None,
            legacy_algorithms: session.legacy,
        };
        self.pending.push(PendingConnect::spawn(title.to_owned(), params, ctx));
    }

    /// Opens the auth chooser for a quick `user@host[:port]` connection.
    fn quick_connect(&mut self) {
        let input = self.quick_connect.trim();
        if input.is_empty() {
            return;
        }
        match parse_target(input) {
            Ok(session) => {
                self.dialog = Dialog::QuickConnect(ConnectAuthForm::new(session));
                self.quick_connect.clear();
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Resolves a quick-connect auth choice into connect material.
    fn resolve_form_auth(&self, form: &ConnectAuthForm) -> Result<AuthMaterial, String> {
        match form.method {
            ConnectAuth::Agent => Ok(AuthMaterial::Agent),
            ConnectAuth::Password => {
                if form.password.is_empty() {
                    return Err("Enter a password.".into());
                }
                Ok(AuthMaterial::Password(form.password.clone()))
            }
            ConnectAuth::VaultSecret => {
                let name = form
                    .secret_name
                    .as_deref()
                    .ok_or("Choose a vault entry.".to_string())?;
                let vault = self.vault.unlocked().ok_or("Unlock the vault first.".to_string())?;
                match vault.get(name) {
                    Some(Secret::Password(p)) => Ok(AuthMaterial::Password(p.clone())),
                    Some(Secret::PrivateKey { pem, passphrase }) => Ok(AuthMaterial::Key {
                        pem: pem.clone(),
                        passphrase: passphrase.clone(),
                    }),
                    None => Err(format!("No vault entry named '{name}'.")),
                }
            }
        }
    }

    /// Turns a session's stored auth choice into connect-ready material.
    fn resolve_auth(&self, auth: &Auth) -> Result<AuthMaterial, String> {
        match auth {
            Auth::Agent => Ok(AuthMaterial::Agent),
            Auth::Password { secret } => match self.vault.unlocked() {
                Some(vault) => match vault.get(secret) {
                    Some(Secret::Password(p)) => Ok(AuthMaterial::Password(p.clone())),
                    _ => Err(format!("No password named '{secret}' in the vault.")),
                },
                None => Err("Unlock the vault to use a saved password.".into()),
            },
            Auth::Key { secret } => match self.vault.unlocked() {
                Some(vault) => match vault.get(secret) {
                    Some(Secret::PrivateKey { pem, passphrase }) => Ok(AuthMaterial::Key {
                        pem: pem.clone(),
                        passphrase: passphrase.clone(),
                    }),
                    _ => Err(format!("No private key named '{secret}' in the vault.")),
                },
                None => Err("Unlock the vault to use a saved key.".into()),
            },
        }
    }

    /// Polls in-flight connections, opening tabs or raising prompts as they resolve.
    fn poll_pending(&mut self, ctx: &egui::Context) {
        let mut i = 0;
        while i < self.pending.len() {
            match self.pending[i].poll() {
                Progress::Waiting => i += 1,
                Progress::Ready(Connected { backend, output }) => {
                    let pending = self.pending.remove(i);
                    let term = Terminal::new(Box::new(backend), output, TermSize::default());
                    self.push_tab(term, pending.title);
                }
                Progress::Failed(message) => {
                    self.pending.remove(i);
                    self.error = Some(message);
                }
                Progress::PromptUnknownHost(info) => {
                    let pending = self.pending.remove(i);
                    self.dialog = Dialog::HostKey {
                        info,
                        changed: false,
                        title: pending.title,
                        params: pending.params,
                    };
                }
                Progress::PromptChangedHost(info) => {
                    let pending = self.pending.remove(i);
                    self.dialog = Dialog::HostKey {
                        info,
                        changed: true,
                        title: pending.title,
                        params: pending.params,
                    };
                }
            }
        }
        if !self.pending.is_empty() {
            // Keep repainting so spinner-like feedback stays live.
            ctx.request_repaint();
        }
    }

    // --- Rendering ----------------------------------------------------------

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
                if shortcut_button(ui, "New local shell", &NEW_TAB) {
                    self.open_local_shell(ui.ctx());
                }
                if ui.add_enabled(!self.tabs.is_empty(), egui::Button::new("Close tab")).clicked() {
                    self.close_tab(self.active);
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("Session", |ui| {
                if ui.button("New session…").clicked() {
                    self.dialog = Dialog::EditSession(SessionForm::new());
                }
            });
            ui.menu_button("Vault", |ui| match &self.vault {
                VaultState::Absent => {
                    if ui.button("Create vault…").clicked() {
                        self.dialog = Dialog::CreateVault {
                            password: String::new(),
                            confirm: String::new(),
                            error: None,
                        };
                    }
                }
                VaultState::Locked => {
                    if ui.button("Unlock vault…").clicked() {
                        self.dialog =
                            Dialog::UnlockVault { password: String::new(), error: None };
                    }
                }
                VaultState::Unlocked(_) => {
                    if ui.button("Manage secrets…").clicked() {
                        self.dialog = Dialog::VaultManager(VaultManagerState::default());
                    }
                    ui.separator();
                    if ui.button("Remember on this device").clicked()
                        && let Some(vault) = self.vault.unlocked()
                        && let Err(e) = vault.enable_keyring_unlock()
                    {
                        self.error = Some(format!("{e:#}"));
                    }
                    if ui.button("Forget on this device").clicked()
                        && let Err(e) = Vault::disable_keyring_unlock()
                    {
                        self.error = Some(format!("{e:#}"));
                    }
                }
            });
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Sessions");
            if ui.small_button("+").on_hover_text("New session").clicked() {
                self.dialog = Dialog::EditSession(SessionForm::new());
            }
        });

        match &self.vault {
            VaultState::Locked => {
                if ui.button("🔒 Unlock vault").clicked() {
                    self.dialog = Dialog::UnlockVault { password: String::new(), error: None };
                }
            }
            VaultState::Absent => {
                ui.label(RichText::new("No vault — passwords/keys disabled").weak());
            }
            VaultState::Unlocked(_) => {}
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Quick:");
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.quick_connect)
                    .hint_text("user@host")
                    .desired_width(f32::INFINITY),
            );
            if edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                self.quick_connect();
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| self.session_tree(ui, ctx));
    }

    fn session_tree(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        // Group session ids by folder so the borrow of `self.sessions` ends
        // before we mutate `self` in response to a click.
        let mut folders: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for session in self.sessions.all() {
            folders
                .entry(session.folder.clone())
                .or_default()
                .push((session.id.clone(), session.name.clone()));
        }

        let mut connect_id = None;
        let mut edit_id = None;
        let mut delete_id = None;

        for (folder, entries) in &folders {
            let mut render = |ui: &mut egui::Ui| {
                for (id, name) in entries {
                    ui.horizontal(|ui| {
                        if ui.selectable_label(false, format!("🖥 {name}")).double_clicked() {
                            connect_id = Some(id.clone());
                        }
                        ui.menu_button("⋮", |ui| {
                            if ui.button("Connect").clicked() {
                                connect_id = Some(id.clone());
                                ui.close();
                            }
                            if ui.button("Edit…").clicked() {
                                edit_id = Some(id.clone());
                                ui.close();
                            }
                            if ui.button("Delete").clicked() {
                                delete_id = Some(id.clone());
                                ui.close();
                            }
                        });
                    });
                }
            };
            if folder.is_empty() {
                render(ui);
            } else {
                egui::CollapsingHeader::new(format!("📁 {folder}"))
                    .default_open(true)
                    .show(ui, &mut render);
            }
        }

        if let Some(id) = connect_id
            && let Some(session) = self.sessions.get(&id).cloned()
        {
            self.start_connect(&session, ctx);
        }
        if let Some(id) = edit_id
            && let Some(session) = self.sessions.get(&id).cloned()
        {
            self.dialog = Dialog::EditSession(SessionForm::from_session(&session));
        }
        if let Some(id) = delete_id
            && let Err(e) = self.sessions.remove(&id)
        {
            self.error = Some(format!("{e:#}"));
        }
    }

    fn tab_strip(&mut self, ui: &mut egui::Ui) {
        let mut close = None;
        egui::ScrollArea::horizontal().show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, tab) in self.tabs.iter().enumerate() {
                    let label: String = tab.label.chars().take(28).collect();
                    if ui.selectable_label(i == self.active, label).clicked() {
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
                for pending in &self.pending {
                    ui.label(RichText::new(format!("⏳ {}", pending.title)).weak());
                }
            });
        });
        if let Some(i) = close {
            self.close_tab(i);
        }
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        match self.tabs.get_mut(self.active) {
            Some(tab) => {
                TerminalView::new(&mut tab.terminal).show(ui);
            }
            None => {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 3.0);
                    ui.heading("Wazowski");
                    ui.add_space(8.0);
                    ui.label(RichText::new("Double-click a session, or open a local shell.").weak());
                    ui.add_space(8.0);
                    if ui.button("New local shell").clicked() {
                        self.open_local_shell(ui.ctx());
                    }
                });
            }
        }
    }

    // --- Dialogs ------------------------------------------------------------

    fn show_dialog(&mut self, ctx: &egui::Context) {
        match &mut self.dialog {
            Dialog::None => {}
            Dialog::UnlockVault { .. } => self.show_unlock_vault(ctx),
            Dialog::CreateVault { .. } => self.show_create_vault(ctx),
            Dialog::EditSession(_) => self.show_edit_session(ctx),
            Dialog::HostKey { .. } => self.show_host_key(ctx),
            Dialog::QuickConnect(_) => self.show_quick_connect(ctx),
            Dialog::VaultManager(_) => self.show_vault_manager(ctx),
        }
    }

    fn show_unlock_vault(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::UnlockVault { password, error } = &mut self.dialog {
            egui::Modal::new(egui::Id::new("unlock-vault")).show(ctx, |ui| {
                ui.set_width(320.0);
                ui.heading("Unlock vault");
                ui.add_space(6.0);
                let field = ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("Master password"),
                );
                field.request_focus();
                if let Some(error) = error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                if field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    submit = true;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Unlock").clicked() {
                        submit = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }
        if submit {
            self.try_unlock_vault();
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn try_unlock_vault(&mut self) {
        let Dialog::UnlockVault { password, error } = &mut self.dialog else { return };
        match Vault::open(self.vault_path.clone(), password) {
            Ok(vault) => {
                self.vault = VaultState::Unlocked(Box::new(vault));
                self.dialog = Dialog::None;
            }
            Err(VaultError::BadPassword) => {
                *error = Some("Incorrect master password.".into());
            }
            Err(e) => *error = Some(format!("{e}")),
        }
    }

    fn show_create_vault(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::CreateVault { password, confirm, error } = &mut self.dialog {
            egui::Modal::new(egui::Id::new("create-vault")).show(ctx, |ui| {
                ui.set_width(340.0);
                ui.heading("Create vault");
                ui.label(
                    RichText::new(
                        "Your passwords and keys are encrypted with this master password.",
                    )
                    .weak(),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("Master password"),
                );
                ui.add(
                    egui::TextEdit::singleline(confirm)
                        .password(true)
                        .hint_text("Confirm password"),
                );
                if let Some(error) = error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Create").clicked() {
                        submit = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }
        if submit {
            self.try_create_vault();
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn try_create_vault(&mut self) {
        let Dialog::CreateVault { password, confirm, error } = &mut self.dialog else { return };
        if password.len() < 8 {
            *error = Some("Use at least 8 characters.".into());
            return;
        }
        if password != confirm {
            *error = Some("The passwords do not match.".into());
            return;
        }
        match Vault::create(self.vault_path.clone(), password) {
            Ok(vault) => {
                self.vault = VaultState::Unlocked(Box::new(vault));
                self.dialog = Dialog::None;
            }
            Err(e) => *error = Some(format!("{e:#}")),
        }
    }

    fn show_edit_session(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        if let Dialog::EditSession(form) = &mut self.dialog {
            let title = if form.id.is_some() { "Edit session" } else { "New session" };
            egui::Modal::new(egui::Id::new("edit-session")).show(ctx, |ui| {
                ui.set_width(380.0);
                ui.heading(title);
                ui.add_space(6.0);
                egui::Grid::new("session-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut form.name);
                    ui.end_row();
                    ui.label("Folder");
                    ui.text_edit_singleline(&mut form.folder);
                    ui.end_row();
                    ui.label("Host");
                    ui.text_edit_singleline(&mut form.host);
                    ui.end_row();
                    ui.label("Port");
                    ui.text_edit_singleline(&mut form.port);
                    ui.end_row();
                    ui.label("Username");
                    ui.text_edit_singleline(&mut form.username);
                    ui.end_row();
                    ui.label("Auth");
                    egui::ComboBox::from_id_salt("auth-method")
                        .selected_text(form.method.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.method, AuthMethod::Agent, "SSH agent");
                            ui.selectable_value(&mut form.method, AuthMethod::Password, "Password");
                            ui.selectable_value(&mut form.method, AuthMethod::Key, "Private key");
                        });
                    ui.end_row();
                    match form.method {
                        AuthMethod::Agent => {}
                        AuthMethod::Password => {
                            ui.label("Password");
                            ui.add(egui::TextEdit::singleline(&mut form.secret_input).password(true));
                            ui.end_row();
                        }
                        AuthMethod::Key => {
                            ui.label("Private key");
                            ui.add(
                                egui::TextEdit::multiline(&mut form.secret_input)
                                    .hint_text("Paste the PEM private key")
                                    .desired_rows(3),
                            );
                            ui.end_row();
                            ui.label("Key passphrase");
                            ui.add(
                                egui::TextEdit::singleline(&mut form.key_passphrase).password(true),
                            );
                            ui.end_row();
                        }
                    }
                });
                ui.add_space(4.0);
                ui.checkbox(&mut form.legacy, "Legacy mode (old switches: SHA-1 KEX, CBC ciphers)")
                    .on_hover_text(
                        "Enables weak but widely compatible algorithms. Use only for old \
                         equipment such as HPE/ProCurve switches.",
                    );
                if form.method != AuthMethod::Agent && self.vault.unlocked().is_none() {
                    ui.colored_label(
                        Color32::LIGHT_YELLOW,
                        "Unlock or create the vault to store this secret.",
                    );
                }
                if let Some(error) = &form.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }
        if save {
            self.try_save_session();
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn try_save_session(&mut self) {
        // Copy the fields out first so the `self.dialog` borrow ends before we
        // touch the vault and session store.
        let Dialog::EditSession(form) = &self.dialog else { return };
        let (id, name, folder, host, port_str, username, method, secret_input, key_passphrase, legacy) = (
            form.id.clone(),
            form.name.trim().to_owned(),
            form.folder.trim().to_owned(),
            form.host.trim().to_owned(),
            form.port.trim().to_owned(),
            form.username.trim().to_owned(),
            form.method,
            form.secret_input.clone(),
            form.key_passphrase.clone(),
            form.legacy,
        );

        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return self.set_form_error("Port must be a number."),
        };
        if host.is_empty() || username.is_empty() {
            return self.set_form_error("Host and username are required.");
        }

        // Build the session, reusing the id when editing so the vault key is stable.
        let mut session = Session::new(&name, &host, &username);
        if let Some(id) = id {
            session.id = id;
        }
        session.folder = folder;
        session.port = port;
        session.legacy = legacy;
        let secret_name = format!("session/{}", session.id);

        session.auth = match method {
            AuthMethod::Agent => Auth::Agent,
            AuthMethod::Password => {
                if !secret_input.is_empty()
                    && let Err(e) = self.store_secret(&secret_name, Secret::Password(secret_input))
                {
                    return self.set_form_error(&e);
                }
                Auth::Password { secret: secret_name }
            }
            AuthMethod::Key => {
                if !secret_input.is_empty() {
                    let passphrase = (!key_passphrase.is_empty()).then_some(key_passphrase);
                    let secret = Secret::PrivateKey { pem: secret_input, passphrase };
                    if let Err(e) = self.store_secret(&secret_name, secret) {
                        return self.set_form_error(&e);
                    }
                }
                Auth::Key { secret: secret_name }
            }
        };

        if let Err(e) = self.sessions.upsert(session) {
            return self.set_form_error(&format!("{e:#}"));
        }
        self.dialog = Dialog::None;
    }

    /// Sets the error line on the open session dialog, if any.
    fn set_form_error(&mut self, message: &str) {
        if let Dialog::EditSession(form) = &mut self.dialog {
            form.error = Some(message.to_owned());
        }
    }

    /// Stores a secret in the vault, requiring it to be unlocked.
    fn store_secret(&mut self, name: &str, secret: Secret) -> Result<(), String> {
        match self.vault.unlocked_mut() {
            Some(vault) => vault.put(name, secret).map_err(|e| format!("{e:#}")),
            None => Err("Unlock or create the vault first.".into()),
        }
    }

    fn show_host_key(&mut self, ctx: &egui::Context) {
        let mut accept = false;
        let mut reject = false;
        if let Dialog::HostKey { info, changed, .. } = &self.dialog {
            let info = info.clone();
            let changed = *changed;
            egui::Modal::new(egui::Id::new("host-key")).show(ctx, |ui| {
                ui.set_width(440.0);
                if changed {
                    ui.heading(RichText::new("⚠ Host key changed").color(Color32::LIGHT_RED));
                    ui.label(
                        "The server's key is different from the one previously recorded. \
                         This can mean a man-in-the-middle attack — or that the server was \
                         reinstalled. Only continue if you expected this.",
                    );
                } else {
                    ui.heading("Unknown host");
                    ui.label("This host's key is not yet trusted. Verify the fingerprint before continuing.");
                }
                ui.add_space(6.0);
                egui::Grid::new("host-key-info").num_columns(2).show(ui, |ui| {
                    ui.label("Host");
                    ui.monospace(format!("{}:{}", info.host, info.port));
                    ui.end_row();
                    ui.label("Algorithm");
                    ui.monospace(&info.algorithm);
                    ui.end_row();
                    ui.label("Fingerprint");
                    ui.monospace(&info.fingerprint);
                    ui.end_row();
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let accept_label = if changed { "Trust the new key" } else { "Trust and connect" };
                    if ui.button(accept_label).clicked() {
                        accept = true;
                    }
                    if ui.button("Cancel").clicked() {
                        reject = true;
                    }
                });
            });
        }
        if accept {
            self.trust_and_reconnect(ctx);
        }
        if reject {
            self.dialog = Dialog::None;
        }
    }

    /// Records the host key as trusted and starts a fresh connection attempt.
    fn trust_and_reconnect(&mut self, ctx: &egui::Context) {
        let Dialog::HostKey { info, title, params, .. } =
            std::mem::replace(&mut self.dialog, Dialog::None)
        else {
            return;
        };
        if let Err(e) = trust_host(&info.host, info.port, &info.key_openssh) {
            self.error = Some(format!("Could not record the host key: {e:#}"));
            return;
        }
        self.pending.push(PendingConnect::spawn(title, params, ctx));
    }

    fn show_quick_connect(&mut self, ctx: &egui::Context) {
        let mut connect = false;
        let mut cancel = false;
        let secret_names = self.vault.unlocked().map(|v| v.names()).unwrap_or_default();
        let vault_unlocked = self.vault.unlocked().is_some();

        if let Dialog::QuickConnect(form) = &mut self.dialog {
            egui::Modal::new(egui::Id::new("quick-connect")).show(ctx, |ui| {
                ui.set_width(360.0);
                ui.heading(format!("Connect to {}", form.session.address()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Auth");
                    egui::ComboBox::from_id_salt("quick-auth")
                        .selected_text(match form.method {
                            ConnectAuth::Agent => "SSH agent",
                            ConnectAuth::Password => "Password",
                            ConnectAuth::VaultSecret => "Vault entry",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.method, ConnectAuth::Agent, "SSH agent");
                            ui.selectable_value(&mut form.method, ConnectAuth::Password, "Password");
                            ui.selectable_value(
                                &mut form.method,
                                ConnectAuth::VaultSecret,
                                "Vault entry",
                            );
                        });
                });
                match form.method {
                    ConnectAuth::Agent => {}
                    ConnectAuth::Password => {
                        let field = ui.add(
                            egui::TextEdit::singleline(&mut form.password)
                                .password(true)
                                .hint_text("Password"),
                        );
                        field.request_focus();
                        if field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            connect = true;
                        }
                    }
                    ConnectAuth::VaultSecret => {
                        if !vault_unlocked {
                            ui.colored_label(Color32::LIGHT_YELLOW, "Unlock the vault first.");
                        } else if secret_names.is_empty() {
                            ui.colored_label(Color32::LIGHT_YELLOW, "The vault has no entries yet.");
                        } else {
                            let selected =
                                form.secret_name.clone().unwrap_or_else(|| "Choose…".into());
                            egui::ComboBox::from_id_salt("quick-secret")
                                .selected_text(selected)
                                .show_ui(ui, |ui| {
                                    for name in &secret_names {
                                        ui.selectable_value(
                                            &mut form.secret_name,
                                            Some(name.clone()),
                                            name,
                                        );
                                    }
                                });
                        }
                    }
                }
                if let Some(error) = &form.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Connect").clicked() {
                        connect = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }

        if connect {
            // Resolve auth, then start the connection outside the dialog borrow.
            let Dialog::QuickConnect(form) = &self.dialog else { return };
            match self.resolve_form_auth(form) {
                Ok(auth) => {
                    let session = form.session.clone();
                    self.dialog = Dialog::None;
                    self.connect_with(&session.address(), &session, auth, ctx);
                }
                Err(e) => {
                    if let Dialog::QuickConnect(form) = &mut self.dialog {
                        form.error = Some(e);
                    }
                }
            }
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_vault_manager(&mut self, ctx: &egui::Context) {
        // Actions collected inside the closure, applied after, to avoid
        // borrowing `self` while the vault/dialog are borrowed.
        enum Action {
            None,
            NewSecret,
            Edit(String),
            Delete(String),
            SaveForm,
            CancelForm,
            Close,
        }
        let mut action = Action::None;
        let names = self.vault.unlocked().map(|v| v.names()).unwrap_or_default();

        if let Dialog::VaultManager(state) = &mut self.dialog {
            egui::Modal::new(egui::Id::new("vault-manager")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading("Vault secrets");
                ui.label(
                    RichText::new("Named passwords and private keys, shareable across sessions.")
                        .weak(),
                );
                ui.add_space(6.0);

                match &mut state.form {
                    None => {
                        egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                            if names.is_empty() {
                                ui.label(RichText::new("No secrets yet.").weak());
                            }
                            for name in &names {
                                ui.horizontal(|ui| {
                                    ui.monospace(name);
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.small_button("Delete").clicked() {
                                                action = Action::Delete(name.clone());
                                            }
                                            if ui.small_button("Edit").clicked() {
                                                action = Action::Edit(name.clone());
                                            }
                                        },
                                    );
                                });
                            }
                        });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("New secret").clicked() {
                                action = Action::NewSecret;
                            }
                            if ui.button("Close").clicked() {
                                action = Action::Close;
                            }
                        });
                    }
                    Some(form) => {
                        let editing = form.original.is_some();
                        ui.heading(if editing { "Edit secret" } else { "New secret" });
                        egui::Grid::new("secret-fields").num_columns(2).show(ui, |ui| {
                            ui.label("Name");
                            ui.add_enabled(
                                !editing,
                                egui::TextEdit::singleline(&mut form.name),
                            );
                            ui.end_row();
                            ui.label("Type");
                            egui::ComboBox::from_id_salt("secret-kind")
                                .selected_text(match form.kind {
                                    SecretKind::Password => "Password",
                                    SecretKind::Key => "Private key",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut form.kind,
                                        SecretKind::Password,
                                        "Password",
                                    );
                                    ui.selectable_value(
                                        &mut form.kind,
                                        SecretKind::Key,
                                        "Private key",
                                    );
                                });
                            ui.end_row();
                            match form.kind {
                                SecretKind::Password => {
                                    ui.label("Password");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut form.value)
                                            .password(true)
                                            .hint_text(if editing { "(unchanged)" } else { "" }),
                                    );
                                    ui.end_row();
                                }
                                SecretKind::Key => {
                                    ui.label("Private key");
                                    ui.add(
                                        egui::TextEdit::multiline(&mut form.value)
                                            .desired_rows(3)
                                            .hint_text(if editing {
                                                "(unchanged)"
                                            } else {
                                                "Paste PEM private key"
                                            }),
                                    );
                                    ui.end_row();
                                    ui.label("Passphrase");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut form.passphrase)
                                            .password(true),
                                    );
                                    ui.end_row();
                                }
                            }
                        });
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui.button("Save").clicked() {
                                action = Action::SaveForm;
                            }
                            if ui.button("Cancel").clicked() {
                                action = Action::CancelForm;
                            }
                        });
                    }
                }

                if let Some(error) = &state.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
            });
        }

        match action {
            Action::None => {}
            Action::Close => self.dialog = Dialog::None,
            Action::NewSecret => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.form = Some(SecretForm::new());
                    state.error = None;
                }
            }
            Action::CancelForm => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.form = None;
                    state.error = None;
                }
            }
            Action::Edit(name) => self.begin_edit_secret(&name),
            Action::Delete(name) => self.delete_secret(&name),
            Action::SaveForm => self.save_secret_form(),
        }
    }

    /// Loads an existing secret into the manager's edit form (values left blank
    /// so they are only overwritten when the user types a new value).
    fn begin_edit_secret(&mut self, name: &str) {
        let kind = match self.vault.unlocked().and_then(|v| v.get(name)) {
            Some(Secret::Password(_)) => SecretKind::Password,
            Some(Secret::PrivateKey { .. }) => SecretKind::Key,
            None => return,
        };
        if let Dialog::VaultManager(state) = &mut self.dialog {
            state.form = Some(SecretForm {
                original: Some(name.to_owned()),
                name: name.to_owned(),
                kind,
                value: String::new(),
                passphrase: String::new(),
            });
            state.error = None;
        }
    }

    fn delete_secret(&mut self, name: &str) {
        let result = match self.vault.unlocked_mut() {
            Some(vault) => vault.remove(name).map(|_| ()),
            None => return,
        };
        if let Dialog::VaultManager(state) = &mut self.dialog
            && let Err(e) = result
        {
            state.error = Some(format!("{e:#}"));
        }
    }

    fn save_secret_form(&mut self) {
        let Dialog::VaultManager(state) = &self.dialog else { return };
        let Some(form) = &state.form else { return };
        let editing = form.original.is_some();
        let name = form.name.trim().to_owned();
        if name.is_empty() {
            return self.set_vault_error("Name is required.");
        }
        // When editing with a blank value, keep the existing secret unchanged.
        if editing && form.value.is_empty() {
            if let Dialog::VaultManager(state) = &mut self.dialog {
                state.form = None;
            }
            return;
        }
        if form.value.is_empty() {
            return self.set_vault_error("Enter a value.");
        }
        let secret = match form.kind {
            SecretKind::Password => Secret::Password(form.value.clone()),
            SecretKind::Key => Secret::PrivateKey {
                pem: form.value.clone(),
                passphrase: (!form.passphrase.is_empty()).then(|| form.passphrase.clone()),
            },
        };
        let result = match self.vault.unlocked_mut() {
            Some(vault) => vault.put(&name, secret).map_err(|e| format!("{e:#}")),
            None => Err("The vault is locked.".into()),
        };
        match result {
            Ok(()) => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.form = None;
                    state.error = None;
                }
            }
            Err(e) => self.set_vault_error(&e),
        }
    }

    fn set_vault_error(&mut self, message: &str) {
        if let Dialog::VaultManager(state) = &mut self.dialog {
            state.error = Some(message.to_owned());
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // Drop tabs whose shells/sessions have ended.
        let before = self.tabs.len();
        self.tabs.retain(|t| !t.terminal.has_exited());
        if self.tabs.len() != before {
            self.active = self.active.min(self.tabs.len().saturating_sub(1));
        }

        self.poll_pending(&ctx);
        // Suppress tab shortcuts while a modal is open so typing a password
        // doesn't also switch tabs.
        if matches!(self.dialog, Dialog::None) {
            self.shortcuts(&ctx);
        }

        egui::Panel::top("menu").show(ui, |ui| self.menu_bar(ui));
        egui::Panel::left("sessions")
            .resizable(true)
            .default_size(240.0)
            .size_range(160.0..=420.0)
            .show(ui, |ui| self.sidebar(ui, &ctx));
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
        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| self.central(ui));

        self.show_dialog(&ctx);
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {}
}

impl AuthMethod {
    fn label(self) -> &'static str {
        match self {
            AuthMethod::Agent => "SSH agent",
            AuthMethod::Password => "Password",
            AuthMethod::Key => "Private key",
        }
    }
}

impl SessionForm {
    fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            folder: String::new(),
            host: String::new(),
            port: "22".into(),
            username: String::new(),
            method: AuthMethod::Agent,
            secret_input: String::new(),
            key_passphrase: String::new(),
            legacy: false,
            error: None,
        }
    }

    fn from_session(session: &Session) -> Self {
        let method = match &session.auth {
            Auth::Agent => AuthMethod::Agent,
            Auth::Password { .. } => AuthMethod::Password,
            Auth::Key { .. } => AuthMethod::Key,
        };
        Self {
            id: Some(session.id.clone()),
            name: session.name.clone(),
            folder: session.folder.clone(),
            host: session.host.clone(),
            port: session.port.to_string(),
            username: session.username.clone(),
            method,
            secret_input: String::new(),
            key_passphrase: String::new(),
            legacy: session.legacy,
            error: None,
        }
    }
}

/// Decides the vault state at startup, trying a keyring-cached key first.
fn initial_vault_state(path: &std::path::Path) -> VaultState {
    if !Vault::exists(path) {
        return VaultState::Absent;
    }
    match Vault::open_with_keyring(path.to_path_buf()) {
        Ok(Some(vault)) => VaultState::Unlocked(Box::new(vault)),
        _ => VaultState::Locked,
    }
}

/// Parses `user@host[:port]` into an agent-auth session for quick connect.
fn parse_target(input: &str) -> Result<Session, String> {
    let (user, rest) = input
        .split_once('@')
        .ok_or_else(|| "Use the form user@host or user@host:port.".to_string())?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse().map_err(|_| "The port must be a number.".to_string())?;
            (host, port)
        }
        None => (rest, 22u16),
    };
    if user.is_empty() || host.is_empty() {
        return Err("Both a username and a host are required.".into());
    }
    let mut session = Session::new(rest, host, user);
    session.port = port;
    Ok(session)
}

/// A menu button that shows its keyboard shortcut; returns whether it was clicked.
fn shortcut_button(ui: &mut egui::Ui, text: &str, shortcut: &KeyboardShortcut) -> bool {
    let button = egui::Button::new(text).shortcut_text(ui.ctx().format_shortcut(shortcut));
    ui.add(button).clicked()
}
