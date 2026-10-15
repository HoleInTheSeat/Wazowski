//! The Wazowski application: tabs, the session-manager sidebar, the encrypted
//! vault, and the dialogs that tie them together.

use std::collections::BTreeMap;
use std::path::PathBuf;

use eframe::egui::{self, Color32, Key, KeyboardShortcut, RichText};
use wazowski_core::session::Auth;
use wazowski_core::{FolderStyle, Secret, Session, SessionStore, Vault, VaultError};
use wazowski_ssh::{
    AuthMaterial, ConnectParams, HostKeyPolicy, UnknownHostKey, trust_host,
};
use wazowski_term::{
    COMMON_BAUDS, LocalPty, SearchQuery, SerialBackend, SerialConfig, SerialDevice, SerialFlow,
    SerialKind, SerialParity, TermSize, Terminal, available_ports, available_ports_detailed,
};

use crate::connect::{Connected, PendingConnect, Progress};
use crate::highlights::{HighlightStore, HighlightRule};
use crate::keybinds::{Action, Keymap};
use crate::macros::{Macro, MacroStore, Step, chord_to_bytes};
use crate::network::{self, HostHit, LocalPort, PortHit, ScanHandle};
use crate::panes::{Home, PaneAction, Panes, SplitDir, SwapTarget};
use crate::settings::{NewTabPlacement, Settings, StartupTab, WebScheme};
use crate::sftp_ui::FileBrowser;
use crate::servers_ui::{ServerEntry, ServerForm, ServersStore};
use crate::sources::{
    self, GitAuthKind, SharedSource, SourceDef, SourceKind, SourcesConfig,
};
use wazowski_servers::{ServerConfig, ServerKind};


/// An open tab: either an established terminal, or a connection in progress.
struct Tab {
    /// Stable id, used to route host-key decisions back to the right tab.
    id: u64,
    /// Label shown on the tab; a session name or "Shell".
    label: String,
    content: TabContent,
    /// Present for SSH tabs: the SFTP file browser for the same session.
    files: Option<FileBrowser>,
    /// How to restart this tab's session once it ends. SSH/serial tabs stay open
    /// when their session closes; local shells auto-close.
    restart: Option<RestartKind>,
    /// Terminal id of this tab's own (original) session, so that when it ends,
    /// any sessions borrowed into split panes can be sent back to their tabs.
    origin_term: Option<u64>,
    /// The saved session this tab connects to (for persisting per-session UI
    /// state like SFTP auto-refresh). `None` for shells and ad-hoc connects.
    session_id: Option<String>,
    /// When this tab's session connected, for the "connected for …" tooltip.
    connected_at: Option<std::time::Instant>,
    /// This tab's terminal font size (seeded from the settings default).
    font_size: f32,
}

/// How a terminal tab's session can be restarted after it ends.
enum RestartKind {
    /// A local shell — auto-closes rather than lingering.
    Shell,
    /// An SSH session; reconnect with these parameters.
    Ssh(Box<ConnectParams>),
    /// A serial connection; reopen this port.
    Serial(Box<SerialConfig>),
}

impl RestartKind {
    /// Whether an ended tab of this kind should stay open (vs. auto-close).
    fn keep_open(&self) -> bool {
        !matches!(self, RestartKind::Shell)
    }
}

enum TabContent {
    /// A connection is being established; shows a live, copyable log.
    Connecting(Box<Connecting>),
    /// One or more working terminals, arranged as a splittable layout.
    Terminal(Box<Panes>),
    /// The quick-servers manager (singleton).
    Servers,
    /// The network toolbox (singleton).
    Network,
    /// This tab's session has been moved into a split pane on another tab.
    Detached { host_tab: u64 },
}

/// Mode for the port scanner: curated common ports or a user spec.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PortMode {
    Common,
    Custom,
}

/// State for the network toolbox tab.
struct NetworkState {
    port_target: String,
    port_mode: PortMode,
    port_spec: String,
    port_scan: Option<ScanHandle<PortHit>>,
    port_open: Vec<(u16, &'static str)>,
    port_error: Option<String>,
    ping: Option<ScanHandle<String>>,
    ping_status: Option<String>,
    subnet_cidr: String,
    subnet_scan: Option<ScanHandle<HostHit>>,
    subnet_hosts: Vec<HostHit>,
    subnet_error: Option<String>,
    local_ports: Option<Vec<LocalPort>>,
    wol_mac: String,
    wol_status: Option<String>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            port_target: String::new(),
            port_mode: PortMode::Common,
            port_spec: "1-1024".into(),
            port_scan: None,
            port_open: Vec::new(),
            port_error: None,
            ping: None,
            ping_status: None,
            subnet_cidr: String::new(),
            subnet_scan: None,
            subnet_hosts: Vec::new(),
            subnet_error: None,
            local_ports: None,
            wol_mac: String::new(),
            wol_status: None,
        }
    }
}

/// A split-pane action requested from the tab strip, applied after the UI pass.
enum SplitButton {
    Split(SplitDir),
    Close,
}

/// A tab context-menu action, applied after the tab strip is drawn.
enum TabAct {
    Duplicate(usize),
    CloseOthers(usize),
}

/// An Extras-settings action, applied after the settings page is drawn.
enum ExtrasAction {
    GrantLowPort,
    InstallIperf,
    Recheck,
}

/// A per-session network tool, launched from the session context menu against
/// the session's host.
#[derive(Clone, Copy)]
enum NetTool {
    Ping,
    PortScanCommon,
    PortScanWellKnown,
    SubnetScan,
}

/// Whether an executable named `name` is on the PATH.
fn has_bin(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else { return false };
    for dir in std::env::split_paths(&path) {
        if dir.join(name).is_file() {
            return true;
        }
        #[cfg(windows)]
        if dir.join(format!("{name}.exe")).is_file() {
            return true;
        }
    }
    false
}

/// Whether this binary already has the `cap_net_bind_service` capability (Linux).
#[cfg(target_os = "linux")]
fn low_port_granted() -> Option<bool> {
    let exe = std::env::current_exe().ok()?;
    let out = std::process::Command::new("getcap").arg(&exe).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).contains("cap_net_bind_service"))
}
#[cfg(not(target_os = "linux"))]
fn low_port_granted() -> Option<bool> {
    None
}

/// The common RDP clients Wazowski can launch, most-preferred first.
const RDP_CLIENTS: &[&str] = if cfg!(windows) {
    &["mstsc", "xfreerdp", "remmina"]
} else if cfg!(target_os = "macos") {
    &["xfreerdp", "remmina"]
} else {
    &["xfreerdp3", "xfreerdp", "wlfreerdp", "remmina"]
};

/// The first installed RDP client on the PATH, if any.
fn detect_rdp_client() -> Option<String> {
    RDP_CLIENTS.iter().find(|name| has_bin(name)).map(|name| (*name).to_owned())
}

/// Best-effort name of the user's default web browser. `None` where it can't
/// be determined (currently anything but Linux, or a missing `xdg-settings`).
fn detect_default_browser() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("xdg-settings")
            .args(["get", "default-web-browser"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let name = String::from_utf8_lossy(&out.stdout).trim().trim_end_matches(".desktop").to_owned();
        (!name.is_empty()).then_some(name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Runs the Extras environment checks.
fn compute_env_checks() -> EnvChecks {
    EnvChecks {
        iperf3: has_bin("iperf3"),
        printing: has_bin("lp") || has_bin("lpr"),
        low_port: low_port_granted(),
        rdp_client: detect_rdp_client(),
        default_browser: detect_default_browser(),
    }
}

/// State of a connecting tab.
struct Connecting {
    /// Parameters, kept so the attempt can be retried (e.g. after trusting a host).
    params: ConnectParams,
    title: String,
    /// The running attempt; `None` once it has failed or is awaiting a host-key decision.
    pending: Option<PendingConnect>,
    /// Captured handshake log lines.
    log: Vec<String>,
    status: String,
    /// Set when the attempt failed; enables Retry.
    error: Option<String>,
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
    UnlockVault { password: String, remember: bool, error: Option<String> },
    CreateVault { password: String, confirm: String, remember: bool, error: Option<String> },
    EditSession(SessionForm),
    HostKey { info: UnknownHostKey, changed: bool, tab_id: u64 },
    QuickConnect(ConnectAuthForm),
    VaultManager(VaultManagerState),
    CreateCredential(CredentialPrompt),
    NewFolder { target: StoreId, parent: String, name: String },
    RenameFolder { target: StoreId, old: String, name: String },
    FolderAppearance { target: StoreId, folder: String, icon: String, color: Option<[u8; 3]> },
    ConfirmDeleteVault,
    ConfirmQuit,
    ConfirmImportVault { src: PathBuf },
    EditServer(ServerForm),
    SerialConnect(SerialForm),
    StartServer { id: String, auto_stop: bool, minutes: String },
    ServerFix {
        title: String,
        message: String,
        command: Option<Vec<String>>,
        retry_id: String,
        /// The remedy only takes effect after a restart (e.g. setcap).
        restart_required: bool,
    },
    AskUsername(UsernamePrompt),
    AddSource(AddSourceForm),
    MissingShare { id: String },
    DropMenu { payload: DragPayload, to: StoreId, folder: String },
    /// The keybindings editor. `capturing` is the action awaiting a new key.
    Keybindings { capturing: Option<Action> },
    /// The macro editor (new or existing).
    MacroEdit(MacroForm),
    /// Confirm running a macro, showing its steps and where they go.
    ConfirmMacro { index: usize, target: MacroTarget },
    /// Program info and links.
    About,
    /// Prompt for a username/password at connect time.
    ConnectCreds(Box<ConnectCredsForm>),
}

/// Fields for the macro editor dialog.
struct MacroForm {
    /// Index in the store if editing an existing macro; `None` for a new one.
    index: Option<usize>,
    name: String,
    steps: Vec<Step>,
    error: Option<String>,
}

/// Fields for the "Add/Edit shared source" dialog (folder or git).
struct AddSourceForm {
    /// `Some` when editing an existing source (keeps its id); `None` to add.
    edit_id: Option<String>,
    name: String,
    kind: SourceKind,
    // Folder:
    path: String,
    // Git:
    url: String,
    branch: String,
    file: String,
    auth: GitAuthKind,
    username: String,
    token: String,
    key_path: String,
    icon: String,
    color: Option<[u8; 3]>,
}

impl Default for AddSourceForm {
    fn default() -> Self {
        Self {
            edit_id: None,
            name: String::new(),
            kind: SourceKind::Folder,
            path: String::new(),
            url: String::new(),
            branch: String::new(),
            file: "wazowski-sessions.toml".into(),
            auth: GitAuthKind::None,
            username: String::new(),
            token: String::new(),
            key_path: String::new(),
            icon: String::new(),
            color: None,
        }
    }
}

impl AddSourceForm {
    /// Prefills the form from an existing source (and its stored HTTPS token).
    fn from_def(def: &SourceDef, token: Option<String>) -> Self {
        Self {
            edit_id: Some(def.id.clone()),
            name: def.name.clone(),
            kind: def.kind,
            path: def.path.to_string_lossy().into_owned(),
            url: def.url.clone(),
            branch: def.branch.clone(),
            file: def.file.clone(),
            auth: def.auth,
            username: def.username.clone(),
            token: token.unwrap_or_default(),
            key_path: def.key_path.clone(),
            icon: def.icon.clone(),
            color: def.color,
        }
    }
}

/// Fields for the "New serial connection" dialog.
struct SerialForm {
    ports: Vec<String>,
    /// Case-insensitive substring filter for the port list (e.g. "usb").
    filter: String,
    /// When true the port was chosen by double-clicking a device, so the picker
    /// is replaced by a read-only label.
    locked_port: bool,
    path: String,
    baud: String,
    data_bits: u8,
    parity: SerialParity,
    stop_bits: u8,
    flow: SerialFlow,
    error: Option<String>,
}

impl SerialForm {
    fn new() -> Self {
        let ports = available_ports();
        let path = ports.first().cloned().unwrap_or_default();
        Self {
            ports,
            filter: String::new(),
            locked_port: false,
            path,
            baud: "115200".into(),
            data_bits: 8,
            parity: SerialParity::None,
            stop_bits: 1,
            flow: SerialFlow::None,
            error: None,
        }
    }
}

/// Prompt for a username at connect time when the session has none.
struct UsernamePrompt {
    title: String,
    session: Session,
    material: AuthMaterial,
    username: String,
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
    /// An open key-generation form, if any.
    gen_form: Option<GenForm>,
    /// The public key from the most recent generation, shown for copying.
    last_public: Option<(String, String)>,
    error: Option<String>,
}

/// Fields for generating a new key pair.
#[derive(Default)]
struct GenForm {
    name: String,
    comment: String,
}

/// Fields for adding or editing one vault entry.
struct SecretForm {
    /// Name of the entry being edited, or `None` when adding.
    original: Option<String>,
    name: String,
    kind: SecretKind,
    /// Optional username stored with the credential (overrides the session's).
    username: String,
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
            username: String::new(),
            value: String::new(),
            passphrase: String::new(),
        }
    }

    /// Builds the vault secret this form describes (value assumed non-empty).
    fn to_secret(&self) -> Secret {
        let username = (!self.username.trim().is_empty()).then(|| self.username.trim().to_owned());
        match self.kind {
            SecretKind::Password => Secret::Password { username, password: self.value.clone() },
            SecretKind::Key => Secret::PrivateKey {
                pem: self.value.clone(),
                passphrase: (!self.passphrase.is_empty()).then(|| self.passphrase.clone()),
                username,
            },
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
    /// Whether to reference an existing vault entry or create a new one.
    source: SecretSource,
    /// Selected existing vault entry name (when `source` is `Existing`).
    existing_name: Option<String>,
    /// Name to store a new credential under (blank → a per-session default).
    new_name: String,
    /// New credential value (password or PEM); blank keeps the existing one when editing.
    secret_input: String,
    key_passphrase: String,
    legacy: bool,
    /// Custom icon (emoji) and label color for the sidebar.
    icon: String,
    color: Option<[u8; 3]>,
    error: Option<String>,
    /// Which store to save into.
    target: StoreId,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMethod {
    Agent,
    Password,
    Key,
}

/// Where a session's credential comes from.
#[derive(PartialEq, Eq, Clone, Copy)]
enum SecretSource {
    /// Reference an existing named vault entry (shareable across sessions).
    Existing,
    /// Create and store a new credential.
    New,
}

/// A successfully resolved credential for a connection.
struct ResolvedAuth {
    material: AuthMaterial,
    /// Username override from the vault entry, if it carried one.
    username: Option<String>,
}

/// Why a session's credential could not be resolved.
enum AuthProblem {
    /// The referenced vault entry does not exist yet; prompt to create it
    /// (MobaXterm-style placeholder: created on first use).
    Missing { name: String, kind: AuthMethod },
    /// The session has no stored password (blank): prompt for it each connect.
    NeedPassword,
    /// Any other problem, already phrased for display.
    Message(String),
}

/// Prompt for a username/password at connect time (blank-password sessions and
/// the "Connect as…" one-off).
#[derive(Clone)]
struct ConnectCredsForm {
    session: Session,
    title: String,
    username: String,
    password: String,
    /// Whether to save the entered credential to the vault.
    save: bool,
    save_name: String,
    /// When saved, also rebind the session to the new vault entry (blank-password
    /// case only, not a one-off "Connect as").
    rebind: bool,
    error: Option<String>,
}

/// Prompt to create a missing named credential, then continue connecting.
struct CredentialPrompt {
    form: SecretForm,
    /// The session to connect once the credential exists.
    then_connect: Session,
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
    next_tab_id: u64,
    /// Set once the user has confirmed quitting, so the window is allowed to close.
    quitting: bool,
    /// Configured shared sources and their live state.
    sources_config: SourcesConfig,
    shared: Vec<SharedSource>,
    /// When shared sources were last auto-synced.
    last_sync: std::time::Instant,
    /// Quick-server configs plus their running state.
    servers_store: ServersStore,
    servers: Vec<ServerEntry>,
    /// A privileged command (install/setcap) running in the background.
    admin_task: Option<AdminTask>,
    /// Multi-exec: mirror typing in the active terminal to all other terminals.
    broadcast: bool,
    /// Configurable keyboard shortcuts.
    keymap: Keymap,
    /// User-defined macros.
    macros: MacroStore,
    /// The macro currently playing, if any.
    macro_run: Option<MacroRun>,
    /// Global, persisted settings.
    settings: Settings,
    /// Held for the process lifetime to enforce single-instance; `None` when
    /// multiple instances are allowed.
    _instance_lock: Option<std::fs::File>,
    /// The find-in-terminals bar, when open.
    find: Option<FindState>,
    /// Which list the left pane is showing.
    sidebar_view: SidebarView,
    /// The network toolbox state.
    network: NetworkState,
    /// Serial devices detected on the system, refreshed periodically for the
    /// sidebar's "Serial connections" group.
    serial_ports: Vec<SerialDevice>,
    serial_ports_at: std::time::Instant,
    /// Whether the dark theme is active (the default).
    dark_mode: bool,
    /// Terminal highlight rules (regex → color).
    highlights: HighlightStore,
    /// Which settings category is shown.
    settings_category: SettingsCategory,
    /// Cached Extras environment checks; recomputed on demand.
    env_checks: Option<EnvChecks>,
}

/// Natural (numeric-aware) comparison of two serial device names, so `ttyUSB2`
/// sorts before `ttyUSB10`.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (mut ai, mut bi) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let xn: String = std::iter::from_fn(|| ai.next_if(|c| c.is_ascii_digit())).collect();
                let yn: String = std::iter::from_fn(|| bi.next_if(|c| c.is_ascii_digit())).collect();
                // Compare by numeric value, then by length (leading zeros).
                let ord = xn
                    .trim_start_matches('0')
                    .len()
                    .cmp(&yn.trim_start_matches('0').len())
                    .then_with(|| xn.cmp(&yn));
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            (Some(x), Some(y)) => {
                let ord = x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase());
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
                ai.next();
                bi.next();
            }
        }
    }
}

/// Detected serial devices, naturally sorted by name.
fn sorted_serial_devices() -> Vec<SerialDevice> {
    let mut devices = available_ports_detailed();
    devices.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    devices
}

/// The left-pane view selector.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SidebarView {
    #[default]
    Sessions,
    Macros,
    Files,
    Settings,
}

/// A settings page category (left-rail selection).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum SettingsCategory {
    #[default]
    General,
    Tabs,
    Vault,
    Terminal,
    Extras,
}

/// Cached results of the Extras environment checks.
#[derive(Clone, Default)]
struct EnvChecks {
    iperf3: bool,
    printing: bool,
    /// `Some(granted)` on Linux; `None` where not applicable.
    low_port: Option<bool>,
    /// Name of the first detected RDP client, if any (for launching saved RDP sessions).
    rdp_client: Option<String>,
    /// Best-effort default web browser name; `None` if it couldn't be determined.
    default_browser: Option<String>,
}

/// State of the find-in-terminals bar.
#[derive(Default)]
struct FindState {
    query: String,
    case_sensitive: bool,
    /// Set to focus the input on the frame the bar opens.
    just_opened: bool,
}

/// Where a macro's steps are sent.
#[derive(Clone, Copy, PartialEq)]
enum MacroTarget {
    /// The focused pane of the active tab.
    ActivePane,
    /// Every pane in the active tab.
    TabPanes,
    /// Every open terminal.
    AllTerminals,
}

impl MacroTarget {
    fn describe(self, count: usize) -> String {
        match self {
            MacroTarget::ActivePane => "the active terminal".to_owned(),
            MacroTarget::TabPanes => format!("all panes in this tab ({count})"),
            MacroTarget::AllTerminals => format!("all open terminals ({count})"),
        }
    }
}

/// A macro being played, advanced one phase at a time from `update`.
struct MacroRun {
    name: String,
    steps: Vec<Step>,
    index: usize,
    /// Terminals the steps are sent to.
    target_ids: Vec<u64>,
    /// Terminal watched by `Expect` steps.
    primary: u64,
    phase: RunPhase,
}

/// What a running macro is doing between steps.
#[derive(Clone)]
enum RunPhase {
    /// Ready to run `steps[index]`.
    Send,
    /// Pausing until this instant (a Delay step).
    Waiting { until: std::time::Instant },
    /// Waiting for `text` to appear, or the deadline to pass (an Expect step).
    Expecting { text: String, deadline: std::time::Instant },
}

/// A privileged helper command running via a worker thread.
struct AdminTask {
    label: String,
    rx: std::sync::mpsc::Receiver<Result<(), String>>,
    /// Server to retry starting if the command succeeds (and no restart needed).
    retry_id: Option<String>,
    /// If set, the grant only applies after restarting Wazowski.
    restart_required: bool,
}

/// Which session store an action targets.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StoreId {
    /// The user's personal local store.
    Local,
    /// A shared source, by its id.
    Shared(String),
}

/// What is being dragged in the session tree.
#[derive(Clone)]
enum DragPayload {
    Session { store: StoreId, id: String },
    Folder { store: StoreId, path: String },
}

/// Adds a broad-coverage fallback font so UI symbol glyphs (arrows, split and
/// broadcast icons, …) render instead of showing missing-glyph boxes.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "dejavu-sans".to_owned(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/DejaVuSans.ttf"
        ))),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(family).or_default().push("dejavu-sans".to_owned());
    }
    ctx.set_fonts(fonts);
}

impl App {
    pub fn new(ctx: &egui::Context, instance_lock: Option<std::fs::File>) -> Self {
        install_fonts(ctx);
        let sessions_path = SessionStore::default_path().unwrap_or_else(|_| "sessions.toml".into());
        let sessions = SessionStore::load(sessions_path).unwrap_or_default();
        let vault_path = Vault::default_path().unwrap_or_else(|_| "vault.enc".into());
        let vault = initial_vault_state(&vault_path);

        // Load shared sources and open each (refreshing its cache from the share).
        let sources_config = SourcesConfig::default_path()
            .and_then(SourcesConfig::load)
            .or_else(|_| SourcesConfig::load("sources.toml".into()))
            .expect("loading a missing sources file yields an empty config");
        let cache = sources::cache_dir().unwrap_or_else(|_| "shared-cache".into());
        let shared = sources_config
            .defs
            .iter()
            .map(|def| SharedSource::open(def.clone(), &cache))
            .collect();

        let servers_store = ServersStore::default_path()
            .and_then(ServersStore::load)
            .or_else(|_| ServersStore::load("servers.toml".into()))
            .expect("loading a missing servers file yields an empty store");
        let servers = servers_store.configs.iter().cloned().map(ServerEntry::new).collect();

        let keymap = Keymap::default_path()
            .and_then(Keymap::load)
            .unwrap_or_else(|_| Keymap::defaults());
        let macros =
            MacroStore::default_path().and_then(MacroStore::load).unwrap_or_else(|_| MacroStore::empty());
        let settings = Settings::load_or_default();

        let mut app = Self {
            tabs: Vec::new(),
            active: 0,
            error: None,
            sessions,
            vault,
            vault_path,
            dialog: Dialog::None,
            quick_connect: String::new(),
            next_tab_id: 1,
            quitting: false,
            sources_config,
            shared,
            last_sync: std::time::Instant::now(),
            servers_store,
            servers,
            admin_task: None,
            broadcast: false,
            keymap,
            macros,
            macro_run: None,
            settings,
            _instance_lock: instance_lock,
            find: None,
            sidebar_view: SidebarView::Sessions,
            network: NetworkState::default(),
            serial_ports: sorted_serial_devices(),
            serial_ports_at: std::time::Instant::now(),
            dark_mode: true,
            highlights: HighlightStore::load_or_default(),
            settings_category: SettingsCategory::General,
            env_checks: None,
        };
        ctx.set_visuals(egui::Visuals::dark());
        app.open_startup_tab(ctx);
        app
    }

    fn new_tab_id(&mut self) -> u64 {
        let id = self.next_tab_id;
        self.next_tab_id += 1;
        id
    }

    // --- Tabs ---------------------------------------------------------------

    fn open_local_shell(&mut self, ctx: &egui::Context) {
        let size = TermSize::default();
        let ctx = ctx.clone();
        match LocalPty::spawn(size, move || ctx.request_repaint()) {
            Ok((pty, output)) => {
                let terminal = Terminal::new(Box::new(pty), output, size);
                let panes = Panes::new(Box::new(terminal));
                self.push_tab("Shell", TabContent::Terminal(Box::new(panes)), None);
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    tab.restart = Some(RestartKind::Shell);
                }
            }
            Err(e) => self.error = Some(format!("Could not start a shell: {e:#}")),
        }
    }

    /// Splits the active tab's focused pane, opening a local shell beside it.
    fn split_active_pane(&mut self, dir: SplitDir, ctx: &egui::Context) {
        let size = TermSize::default();
        let ctx = ctx.clone();
        let term = match LocalPty::spawn(size, move || ctx.request_repaint()) {
            Ok((pty, output)) => Terminal::new(Box::new(pty), output, size),
            Err(e) => {
                self.error = Some(format!("Could not start a shell: {e:#}"));
                return;
            }
        };
        if let Some(tab) = self.tabs.get_mut(self.active)
            && let TabContent::Terminal(panes) = &mut tab.content
        {
            panes.split(dir, Box::new(term));
        }
    }

    /// Closes the active tab's focused pane (no effect if it's the only one). A
    /// moved-in session is returned to its home tab rather than dropped.
    fn close_active_pane(&mut self) {
        let taken = if let Some(tab) = self.tabs.get_mut(self.active)
            && let TabContent::Terminal(panes) = &mut tab.content
        {
            panes.close_focused()
        } else {
            None
        };
        if let Some((term, Some(home))) = taken {
            self.return_home(home, term);
        }
    }

    /// Returns a moved-in terminal to its home tab, restoring it as that tab's
    /// session. If the home tab is gone, the terminal is simply dropped.
    fn return_home(&mut self, home: Home, term: Box<Terminal>) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == home.tab_id) {
            tab.origin_term = Some(term.id());
            tab.content = TabContent::Terminal(Box::new(Panes::new(term)));
            tab.connected_at.get_or_insert_with(std::time::Instant::now);
        }
    }

    /// Applies a split-pane title-bar request on the active tab.
    fn handle_pane_action(&mut self, action: PaneAction, ctx: &egui::Context) {
        match action {
            PaneAction::NewShell(leaf) => {
                let size = TermSize::default();
                let repaint = ctx.clone();
                let term = match LocalPty::spawn(size, move || repaint.request_repaint()) {
                    Ok((pty, output)) => Terminal::new(Box::new(pty), output, size),
                    Err(e) => {
                        self.error = Some(format!("Could not start a shell: {e:#}"));
                        return;
                    }
                };
                let old = self.active_panes_mut().and_then(|p| {
                    p.replace_leaf(leaf, Box::new(term), None)
                });
                if let Some((old_term, Some(home))) = old {
                    self.return_home(home, old_term);
                }
            }
            PaneAction::Return(leaf) | PaneAction::ClosePane(leaf) => {
                let taken = self.active_panes_mut().and_then(|p| p.remove_leaf(leaf));
                if let Some((term, Some(home))) = taken {
                    self.return_home(home, term);
                }
            }
            PaneAction::CloseOthers(leaf) => {
                let others = self.active_panes_mut().map(|p| p.keep_only(leaf)).unwrap_or_default();
                for (term, home) in others {
                    if let Some(home) = home {
                        self.return_home(home, term);
                    }
                }
            }
            PaneAction::Swap { leaf, from_tab } => self.swap_into_pane(leaf, from_tab),
        }
    }

    /// The active tab's panes, if it is a terminal tab.
    fn active_panes_mut(&mut self) -> Option<&mut Panes> {
        match self.tabs.get_mut(self.active).map(|t| &mut t.content) {
            Some(TabContent::Terminal(panes)) => Some(panes),
            _ => None,
        }
    }

    /// Moves `from_tab`'s session into the active tab's `leaf` pane. The old pane
    /// occupant is returned home (if moved-in) or dropped (an owned shell).
    fn swap_into_pane(&mut self, leaf: u64, from_tab: u64) {
        let host_id = match self.tabs.get(self.active) {
            Some(t) => t.id,
            None => return,
        };
        let Some(from_idx) = self.tabs.iter().position(|t| t.id == from_tab) else { return };
        if self.tabs[from_idx].id == host_id {
            return;
        }
        let label = self.tabs[from_idx].label.clone();
        let term = match &mut self.tabs[from_idx].content {
            TabContent::Terminal(panes) => panes.take_single(),
            _ => None,
        };
        let Some(term) = term else { return };
        // The source tab becomes a placeholder pointing at its new host. Its SFTP
        // browser (if any) is kept so the Files panel returns when the session
        // comes back; it just isn't shown while the tab is a placeholder.
        self.tabs[from_idx].content = TabContent::Detached { host_tab: host_id };

        let home = Home { tab_id: from_tab, label };
        let old = self.active_panes_mut().and_then(|p| p.replace_leaf(leaf, term, Some(home)));
        if let Some((old_term, Some(old_home))) = old {
            self.return_home(old_home, old_term);
        }
    }

    /// Steps the active serial tab's baud rate up (`delta > 0`) or down through
    /// the common rates, applying it live and remembering it for a restart.
    fn adjust_baud(&mut self, delta: i32) {
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        let current = match &tab.restart {
            Some(RestartKind::Serial(cfg)) => cfg.baud,
            _ => return,
        };
        let idx = COMMON_BAUDS.iter().position(|&b| b == current).unwrap_or_else(|| {
            COMMON_BAUDS
                .iter()
                .enumerate()
                .min_by_key(|(_, b)| (i64::from(**b) - i64::from(current)).abs())
                .map(|(i, _)| i)
                .unwrap_or(0)
        });
        let new_idx = (idx as i32 + delta).clamp(0, COMMON_BAUDS.len() as i32 - 1) as usize;
        let new_baud = COMMON_BAUDS[new_idx];
        if new_baud == current {
            return;
        }
        let applied = match &mut tab.content {
            TabContent::Terminal(panes) => {
                let focused = panes.focused_id();
                panes.get_mut(focused).is_some_and(|t| t.set_baud(new_baud))
            }
            _ => false,
        };
        if applied && let Some(RestartKind::Serial(cfg)) = &mut tab.restart {
            cfg.baud = new_baud;
        }
    }

    /// Sets the active tab's terminal font size (clamped). Per-tab, so it doesn't
    /// disturb other tabs or the configured default.
    fn set_active_font_size(&mut self, size: f32) {
        if let Some(tab) = self.tabs.get_mut(self.active) {
            tab.font_size = size.clamp(8.0, 40.0);
        }
    }

    /// Adjusts the active tab's font size by `delta` points.
    fn nudge_active_font_size(&mut self, delta: f32) {
        if let Some(tab) = self.tabs.get(self.active) {
            self.set_active_font_size(tab.font_size + delta);
        }
    }

    /// The active tab's live serial baud rate, if it is a serial terminal.
    fn active_serial_baud(&self) -> Option<u32> {
        let tab = self.tabs.get(self.active)?;
        match (&tab.content, &tab.restart) {
            (TabContent::Terminal(_), Some(RestartKind::Serial(cfg))) => Some(cfg.baud),
            _ => None,
        }
    }

    /// Opens the first tab at startup per the user's setting.
    fn open_startup_tab(&mut self, ctx: &egui::Context) {
        match self.settings.startup_tab.clone() {
            StartupTab::None => {}
            StartupTab::LocalShell => self.open_local_shell(ctx),
            StartupTab::Session(id) => match self.sessions.get(&id).cloned() {
                Some(session) => {
                    self.remember_recent(&id);
                    self.start_connect(&session, ctx);
                }
                None => self.open_local_shell(ctx),
            },
        }
    }

    /// Opens (or focuses) the singleton Network toolbox tab.
    fn open_network_tab(&mut self) {
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.content, TabContent::Network)) {
            self.active = i;
        } else {
            self.push_tab("Network", TabContent::Network, None);
        }
    }

    fn push_tab(&mut self, label: impl Into<String>, content: TabContent, files: Option<FileBrowser>) {
        self.push_tab_at(label, content, files, false);
    }

    /// Inserts a tab and focuses it. With `force_adjacent` (a duplicate) or the
    /// "Always" placement setting, it opens right after the current tab;
    /// otherwise it appends at the end.
    fn push_tab_at(
        &mut self,
        label: impl Into<String>,
        content: TabContent,
        files: Option<FileBrowser>,
        force_adjacent: bool,
    ) {
        let id = self.new_tab_id();
        let origin_term = match &content {
            TabContent::Terminal(panes) => panes.ids().first().copied(),
            _ => None,
        };
        let connected_at =
            matches!(content, TabContent::Terminal(_)).then(std::time::Instant::now);
        let tab = Tab {
            id,
            label: label.into(),
            content,
            files,
            restart: None,
            origin_term,
            session_id: None,
            connected_at,
            font_size: self.settings.terminal_font_size,
        };
        let adjacent = force_adjacent || self.settings.new_tab_placement == NewTabPlacement::Always;
        let index = if adjacent && !self.tabs.is_empty() {
            (self.active + 1).min(self.tabs.len())
        } else {
            self.tabs.len()
        };
        self.tabs.insert(index, tab);
        self.active = index;
    }

    /// A hover tooltip for a tab: session info plus connection duration/status.
    fn tab_hint(&self, tab: &Tab) -> String {
        let mut lines = Vec::new();
        if let Some(sid) = &tab.session_id
            && let Some((_, session)) = self.find_session_anywhere(sid)
        {
            lines.push(session_hint(&session));
        } else {
            match &tab.restart {
                Some(RestartKind::Ssh(p)) => {
                    lines.push(format!("SSH · {}@{}:{}", p.username, p.host, p.port))
                }
                Some(RestartKind::Serial(c)) => {
                    lines.push(format!("Serial · {} @ {} baud", c.path, c.baud))
                }
                Some(RestartKind::Shell) => lines.push("Local shell".to_owned()),
                None => {}
            }
        }
        let ended = matches!(&tab.content, TabContent::Terminal(p) if p.all_exited());
        if matches!(&tab.content, TabContent::Connecting(_)) {
            lines.push("connecting…".to_owned());
        } else if ended {
            lines.push("disconnected".to_owned());
        } else if let Some(at) = tab.connected_at {
            lines.push(format!("connected for {}", fmt_duration(at.elapsed())));
        }
        lines.join("\n")
    }

    /// Opens the same session as `index` in a new tab.
    fn duplicate_tab(&mut self, index: usize, ctx: &egui::Context) {
        let Some(tab) = self.tabs.get(index) else { return };
        let title = tab.label.clone();
        let session_id = tab.session_id.clone();
        match &tab.restart {
            Some(RestartKind::Ssh(p)) => {
                let params = (**p).clone();
                self.open_connecting_tab(title, params, session_id, ctx);
            }
            Some(RestartKind::Serial(c)) => {
                let config = (**c).clone();
                if let Err(e) = self.open_serial_config(config, ctx) {
                    self.error = Some(format!("Could not reopen the serial port: {e:#}"));
                }
            }
            Some(RestartKind::Shell) | None => self.open_local_shell(ctx),
        }
        // Honour the "when duplicating" placement by moving the new tab adjacent.
        if self.settings.new_tab_placement == NewTabPlacement::WhenDuplicating {
            let new = self.active;
            let dest = (index + 1).min(self.tabs.len().saturating_sub(1));
            if new != dest {
                let t = self.tabs.remove(new);
                self.tabs.insert(dest, t);
                self.active = dest;
            }
        }
    }

    fn close_tab(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }
        match &mut self.tabs[index].content {
            // Send any moved-in sessions back to their home tabs first.
            TabContent::Terminal(panes) => {
                let moved = panes.drain_moved();
                for (term, home) in moved {
                    self.return_home(home, term);
                }
            }
            // Closing a detached placeholder: keep its session alive in the host
            // by making that pane the host's own.
            TabContent::Detached { host_tab } => {
                let host = *host_tab;
                let my_id = self.tabs[index].id;
                if let Some(host_tab) = self.tabs.iter_mut().find(|t| t.id == host)
                    && let TabContent::Terminal(panes) = &mut host_tab.content
                {
                    panes.clear_home(my_id);
                }
            }
            _ => {}
        }
        self.tabs.remove(index);
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len().saturating_sub(1);
        }
    }

    // --- Connecting ---------------------------------------------------------

    /// Starts connecting to `session`, resolving its credentials from the vault.
    /// A missing named credential opens a prompt to create it, then continues.
    fn start_connect(&mut self, session: &Session, ctx: &egui::Context) {
        match self.resolve_auth(&session.auth) {
            Ok(resolved) => self.connect_with(&session.name, session, resolved, ctx),
            Err(AuthProblem::Missing { name, kind }) => {
                let mut form = SecretForm::new();
                form.name = name;
                form.username = session.username.clone();
                form.kind = match kind {
                    AuthMethod::Key => SecretKind::Key,
                    _ => SecretKind::Password,
                };
                self.dialog = Dialog::CreateCredential(CredentialPrompt {
                    form,
                    then_connect: session.clone(),
                });
            }
            Err(AuthProblem::NeedPassword) => {
                self.dialog = Dialog::ConnectCreds(Box::new(ConnectCredsForm {
                    username: session.username.clone(),
                    password: String::new(),
                    save: false,
                    save_name: self.default_secret_name(&session.name, &session.host),
                    rebind: true,
                    error: None,
                    title: session.name.clone(),
                    session: session.clone(),
                }));
            }
            Err(AuthProblem::Message(m)) => self.error = Some(m),
        }
    }

    /// Opens the "Connect as…" one-off credential prompt for a session.
    fn connect_as(&mut self, session: &Session) {
        self.dialog = Dialog::ConnectCreds(Box::new(ConnectCredsForm {
            username: String::new(),
            password: String::new(),
            save: false,
            save_name: self.default_secret_name(&session.name, &session.host),
            rebind: false,
            error: None,
            title: format!("{} (connect as…)", session.name),
            session: session.clone(),
        }));
    }

    /// Spawns a connection to `session` with already-resolved credentials,
    /// letting the vault entry's username override the session's. If no username
    /// is available anywhere, prompts for one (without persisting it).
    fn connect_with(
        &mut self,
        title: &str,
        session: &Session,
        resolved: ResolvedAuth,
        ctx: &egui::Context,
    ) {
        let username = resolved.username.unwrap_or_else(|| session.username.clone());
        if username.trim().is_empty() {
            self.dialog = Dialog::AskUsername(UsernamePrompt {
                title: title.to_owned(),
                session: session.clone(),
                material: resolved.material,
                username: String::new(),
            });
            return;
        }
        let mut session = session.clone();
        session.username = username;
        let session_id = self.saved_session_id(&session);
        let params = self.params_for(&session, resolved.material);
        self.open_connecting_tab(title.to_owned(), params, session_id, ctx);
    }

    /// Builds connect parameters for a session with resolved auth material.
    fn params_for(&self, session: &Session, material: AuthMaterial) -> ConnectParams {
        ConnectParams {
            host: session.host.clone(),
            port: session.port,
            username: session.username.clone(),
            auth: material,
            policy: HostKeyPolicy::Strict,
            size: TermSize::default(),
            known_hosts: None,
            legacy_algorithms: session.legacy,
        }
    }

    /// Opens a tab that shows connection progress and the handshake log.
    /// `session_id` is the saved session (if any) for persisting per-session UI.
    fn open_connecting_tab(
        &mut self,
        title: String,
        params: ConnectParams,
        session_id: Option<String>,
        ctx: &egui::Context,
    ) {
        let pending = PendingConnect::spawn(params.clone(), ctx);
        let connecting = Connecting {
            params,
            title: title.clone(),
            pending: Some(pending),
            log: Vec::new(),
            status: "Connecting…".into(),
            error: None,
        };
        self.push_tab(title, TabContent::Connecting(Box::new(connecting)), None);
        if let Some(tab) = self.tabs.get_mut(self.active) {
            tab.session_id = session_id;
        }
    }

    /// The saved-session id for a session, if it exists in some store (so ad-hoc
    /// quick connects, whose ids aren't stored, don't persist state).
    fn saved_session_id(&self, session: &Session) -> Option<String> {
        self.find_session_anywhere(&session.id).map(|_| session.id.clone())
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
    fn resolve_form_auth(&self, form: &ConnectAuthForm) -> Result<ResolvedAuth, String> {
        match form.method {
            ConnectAuth::Agent => Ok(ResolvedAuth { material: AuthMaterial::Agent, username: None }),
            ConnectAuth::Password => {
                if form.password.is_empty() {
                    return Err("Enter a password.".into());
                }
                Ok(ResolvedAuth {
                    material: AuthMaterial::Password(form.password.clone()),
                    username: None,
                })
            }
            ConnectAuth::VaultSecret => {
                let name = form
                    .secret_name
                    .as_deref()
                    .ok_or("Choose a vault entry.".to_string())?;
                let vault = self.vault.unlocked().ok_or("Unlock the vault first.".to_string())?;
                let secret = vault.get(name).ok_or(format!("No vault entry named '{name}'."))?;
                Ok(ResolvedAuth { material: material_from(secret), username: secret.username().map(str::to_owned) })
            }
        }
    }

    /// Turns a session's stored auth choice into connect-ready material, or a
    /// problem the caller can act on (e.g. a missing credential to create).
    fn resolve_auth(&self, auth: &Auth) -> Result<ResolvedAuth, AuthProblem> {
        let (name, kind) = match auth {
            Auth::Agent => {
                return Ok(ResolvedAuth { material: AuthMaterial::Agent, username: None });
            }
            Auth::Password { secret } if secret.is_empty() => return Err(AuthProblem::NeedPassword),
            Auth::Password { secret } => (secret, AuthMethod::Password),
            Auth::Key { secret } => (secret, AuthMethod::Key),
        };
        let vault = self
            .vault
            .unlocked()
            .ok_or(AuthProblem::Message("Unlock the vault to use saved credentials.".into()))?;
        match vault.get(name) {
            Some(secret) => Ok(ResolvedAuth {
                material: material_from(secret),
                username: secret.username().map(str::to_owned),
            }),
            None => Err(AuthProblem::Missing { name: name.clone(), kind }),
        }
    }

    /// Polls connecting tabs, turning them into terminals or raising prompts.
    fn poll_connections(&mut self, ctx: &egui::Context) {
        let mut any_active = false;
        for index in 0..self.tabs.len() {
            if !matches!(self.tabs[index].content, TabContent::Connecting(_)) {
                continue;
            }
            // Precompute (needs &self) before taking the &mut Connecting borrow.
            let auto_refresh = self.tabs[index]
                .session_id
                .as_ref()
                .and_then(|id| self.find_session_anywhere(id))
                .is_some_and(|(_, s)| s.sftp_auto_refresh);
            let TabContent::Connecting(c) = &mut self.tabs[index].content else { continue };
            let Some(pending) = &c.pending else { continue };
            pending.drain_log(&mut c.log);
            match pending.poll() {
                Progress::Waiting => any_active = true,
                Progress::Ready(Connected { backend, output }) => {
                    // Grab an SFTP handle before the backend is boxed into the terminal.
                    let mut files = FileBrowser::new(backend.sftp());
                    // Restore this session's remembered SFTP auto-refresh setting.
                    files.set_auto_refresh(auto_refresh);
                    let params = c.params.clone();
                    let term = Terminal::new(Box::new(backend), output, TermSize::default());
                    let term_id = term.id();
                    let tab = &mut self.tabs[index];
                    tab.content = TabContent::Terminal(Box::new(Panes::new(Box::new(term))));
                    tab.files = Some(files);
                    tab.restart = Some(RestartKind::Ssh(Box::new(params)));
                    tab.origin_term = Some(term_id);
                    tab.connected_at = Some(std::time::Instant::now());
                }
                Progress::Failed(message) => {
                    c.pending = None;
                    c.status = "Connection failed".into();
                    c.error = Some(message);
                }
                Progress::PromptUnknownHost(info) => {
                    c.pending = None;
                    c.status = "Awaiting host-key confirmation".into();
                    self.dialog = Dialog::HostKey {
                        info,
                        changed: false,
                        tab_id: self.tabs[index].id,
                    };
                }
                Progress::PromptChangedHost(info) => {
                    c.pending = None;
                    c.status = "Awaiting host-key confirmation".into();
                    self.dialog = Dialog::HostKey {
                        info,
                        changed: true,
                        tab_id: self.tabs[index].id,
                    };
                }
            }
        }
        if any_active {
            ctx.request_repaint();
        }
    }

    /// Restarts a connecting tab's attempt (used after trusting a host key).
    fn retry_tab(&mut self, tab_id: u64, ctx: &egui::Context) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) else { return };
        let TabContent::Connecting(c) = &mut tab.content else { return };
        c.log.clear();
        c.error = None;
        c.status = "Connecting…".into();
        c.pending = Some(PendingConnect::spawn(c.params.clone(), ctx));
    }

    // --- Quick servers ------------------------------------------------------

    /// Opens (or focuses) the singleton Servers tab.
    fn open_servers_tab(&mut self) {
        if let Some(i) = self.tabs.iter().position(|t| matches!(t.content, TabContent::Servers)) {
            self.active = i;
        } else {
            self.push_tab("Servers", TabContent::Servers, None);
        }
    }

    /// Drains logs from running servers; returns whether any are running.
    fn poll_servers(&mut self) -> bool {
        let now = std::time::Instant::now();
        let mut any = false;
        let mut expired = Vec::new();
        for entry in &mut self.servers {
            if let Some(running) = &entry.running {
                running.drain_log(&mut entry.log);
                any = true;
                if entry.stop_at.is_some_and(|t| now >= t) {
                    entry.log.push("Auto-stop timer elapsed.".into());
                    expired.push(entry.config.id.clone());
                }
            }
        }
        for id in expired {
            self.stop_server(&id);
        }
        any
    }

    /// Starts a server; `auto_stop` schedules an automatic stop after `minutes`.
    /// A typed failure opens a fix-it prompt (privileged port, missing iperf3).
    fn start_server(&mut self, id: &str, auto_stop: Option<u64>, ctx: &egui::Context) {
        let Some(entry) = self.servers.iter_mut().find(|e| e.config.id == id) else { return };
        if entry.is_running() {
            return;
        }
        entry.log.clear();
        let ctx2 = ctx.clone();
        match wazowski_servers::start(&entry.config, move || ctx2.request_repaint()) {
            Ok(running) => {
                entry.running = Some(running);
                entry.stop_at = auto_stop
                    .map(|m| std::time::Instant::now() + std::time::Duration::from_secs(m * 60));
            }
            Err(e) => self.handle_start_error(id, e),
        }
    }

    /// Turns a start failure into a helpful fix-it dialog where possible.
    fn handle_start_error(&mut self, id: &str, e: wazowski_servers::StartError) {
        use wazowski_servers::StartError;
        match e {
            StartError::PrivilegedPort(port) => {
                let command = wazowski_servers::low_port_setcap_command();
                let mut message = format!(
                    "Port {port} is privileged (below 1024). Pick a port of 1024 or higher, \
                     or grant this app permission to use low ports."
                );
                if command.is_none() {
                    message.push_str("\n\nGranting low-port permission isn't available on this platform.");
                }
                self.dialog = Dialog::ServerFix {
                    title: "Privileged port".into(),
                    message,
                    command,
                    retry_id: id.to_owned(),
                    restart_required: true,
                };
            }
            StartError::NotInstalled(bin) => {
                let command = wazowski_servers::iperf_install_command();
                let message = match &command {
                    Some(cmd) => format!("{bin} isn't installed. Install it with: {}", cmd.join(" ")),
                    None => format!(
                        "{bin} isn't installed, and no package manager was detected. Install it \
                         with your system's package manager, then try again."
                    ),
                };
                self.dialog = Dialog::ServerFix {
                    title: format!("{bin} not installed"),
                    message,
                    command,
                    retry_id: id.to_owned(),
                    restart_required: false,
                };
            }
            StartError::Other(m) => {
                if let Some(entry) = self.servers.iter_mut().find(|e| e.config.id == id) {
                    entry.log.push(format!("Failed to start: {m}"));
                }
                self.error = Some(format!("Could not start the server: {m}"));
            }
        }
    }

    fn stop_server(&mut self, id: &str) {
        if let Some(entry) = self.servers.iter_mut().find(|e| e.config.id == id) {
            if let Some(running) = entry.running.take() {
                running.stop();
                entry.log.push("Stopped.".into());
            }
            entry.stop_at = None;
        }
    }

    /// Runs a privileged command (via pkexec on Linux) on a worker thread.
    fn run_admin(
        &mut self,
        label: String,
        mut command: Vec<String>,
        retry_id: Option<String>,
        restart_required: bool,
    ) {
        if command.is_empty() {
            return;
        }
        if wazowski_servers::needs_pkexec() {
            command.insert(0, "pkexec".into());
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = std::process::Command::new(&command[0])
                .args(&command[1..])
                .status()
                .map_err(|e| e.to_string())
                .and_then(|s| {
                    if s.success() { Ok(()) } else { Err(format!("command failed ({s})")) }
                });
            let _ = tx.send(result);
        });
        self.admin_task = Some(AdminTask { label, rx, retry_id, restart_required });
    }

    /// Polls a running privileged command. On success, either retries the start
    /// (install) or tells the user to restart (setcap takes effect on re-exec).
    fn poll_admin(&mut self, ctx: &egui::Context) {
        let Some(task) = &self.admin_task else { return };
        match task.rx.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(300));
            }
            Ok(Ok(())) => {
                let task = self.admin_task.take().expect("just checked");
                if task.restart_required {
                    self.dialog = Dialog::ServerFix {
                        title: "Permission granted".into(),
                        message: "Low-port permission was granted, but it only takes effect after \
                                  a restart. Restart Wazowski, then start the server — or use a \
                                  port of 1024 or higher to avoid needing this."
                            .into(),
                        command: None,
                        retry_id: String::new(),
                        restart_required: false,
                    };
                } else if let Some(id) = task.retry_id {
                    self.dialog =
                        Dialog::StartServer { id, auto_stop: true, minutes: "60".into() };
                }
            }
            Ok(Err(e)) => {
                let label = self.admin_task.take().map(|t| t.label).unwrap_or_default();
                self.error = Some(format!("{label} failed: {e}"));
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.admin_task = None;
            }
        }
    }

    // --- Rendering ----------------------------------------------------------

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let triggered = |action: Action, ctx: &egui::Context, map: &Keymap| {
            let sc = map.get(action);
            ctx.input_mut(|i| i.consume_shortcut(&sc))
        };
        if triggered(Action::NewShell, ctx, &self.keymap) {
            self.open_local_shell(ctx);
        }
        if triggered(Action::CloseTab, ctx, &self.keymap) && !self.tabs.is_empty() {
            self.close_tab(self.active);
        }
        if !self.tabs.is_empty() {
            let n = self.tabs.len();
            if triggered(Action::NextTab, ctx, &self.keymap) {
                self.active = (self.active + 1) % n;
            }
            if triggered(Action::PrevTab, ctx, &self.keymap) {
                self.active = (self.active + n - 1) % n;
            }
        }
        if triggered(Action::SplitRight, ctx, &self.keymap) {
            self.split_active_pane(SplitDir::Horizontal, ctx);
        }
        if triggered(Action::SplitDown, ctx, &self.keymap) {
            self.split_active_pane(SplitDir::Vertical, ctx);
        }
        if triggered(Action::ClosePane, ctx, &self.keymap) {
            self.close_active_pane();
        }
        if triggered(Action::ToggleBroadcast, ctx, &self.keymap) {
            self.broadcast = !self.broadcast;
        }
        if triggered(Action::Find, ctx, &self.keymap) {
            match &self.find {
                Some(_) => self.find = None,
                None => self.find = Some(FindState { just_opened: true, ..Default::default() }),
            }
        }
        if triggered(Action::BaudUp, ctx, &self.keymap) {
            self.adjust_baud(1);
        }
        if triggered(Action::BaudDown, ctx, &self.keymap) {
            self.adjust_baud(-1);
        }
        if triggered(Action::ViewSessions, ctx, &self.keymap) {
            self.sidebar_view = SidebarView::Sessions;
        }
        if triggered(Action::ViewMacros, ctx, &self.keymap) {
            self.sidebar_view = SidebarView::Macros;
        }
        if triggered(Action::ViewFiles, ctx, &self.keymap) {
            self.sidebar_view = SidebarView::Files;
        }
        if triggered(Action::FontSizeUp, ctx, &self.keymap) {
            self.nudge_active_font_size(1.0);
        }
        if triggered(Action::FontSizeDown, ctx, &self.keymap) {
            self.nudge_active_font_size(-1.0);
        }
        if triggered(Action::FontSizeReset, ctx, &self.keymap) {
            self.set_active_font_size(self.settings.terminal_font_size);
        }
        // Action::RunMacro is handled (and consumed) by the macros feature.
        self.macro_shortcut(ctx);
    }

    /// Switches the left pane to the Macros view when the Run-macro shortcut fires.
    fn macro_shortcut(&mut self, ctx: &egui::Context) {
        let sc = self.keymap.get(Action::RunMacro);
        if ctx.input_mut(|i| i.consume_shortcut(&sc)) {
            self.sidebar_view = SidebarView::Macros;
        }
    }

    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("About Wazowski").clicked() {
                    self.dialog = Dialog::About;
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
                ui.separator();
                if ui.button("Add shared source…").clicked() {
                    self.dialog = Dialog::AddSource(AddSourceForm::default());
                }
            });
            ui.menu_button("Tools", |ui| {
                if ui.button("Quick servers").clicked() {
                    self.open_servers_tab();
                }
                if ui.button("Network scanner").clicked() {
                    self.open_network_tab();
                }
                ui.separator();
                if ui.button("Keybindings…").clicked() {
                    self.dialog = Dialog::Keybindings { capturing: None };
                }
            });
            ui.menu_button("Vault", |ui| {
                let exists = !matches!(self.vault, VaultState::Absent);
                match &self.vault {
                    VaultState::Absent => {
                        if ui.button("Create vault…").clicked() {
                            self.dialog = Dialog::CreateVault {
                                password: String::new(),
                                confirm: String::new(),
                                remember: false,
                                error: None,
                            };
                        }
                    }
                    VaultState::Locked => {
                        if ui.button("Unlock vault…").clicked() {
                            self.dialog = Dialog::UnlockVault {
                                password: String::new(),
                                remember: false,
                                error: None,
                            };
                        }
                    }
                    VaultState::Unlocked(_) => {
                        if ui.button("Manage secrets…").clicked() {
                            self.dialog = Dialog::VaultManager(VaultManagerState::default());
                        }
                    }
                }
                ui.separator();
                if ui.button("Import vault…").clicked() {
                    self.import_vault();
                }
                if exists {
                    if ui.button("Back up vault…").clicked() {
                        self.backup_vault();
                    }
                    if ui.button("Delete vault…").clicked() {
                        self.dialog = Dialog::ConfirmDeleteVault;
                    }
                }
            });
            // Far-right theme toggle.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (icon, hint) = if self.dark_mode {
                    ("☀", "Switch to light mode")
                } else {
                    ("🌙", "Switch to dark mode")
                };
                if ui.button(icon).on_hover_text(hint).clicked() {
                    self.dark_mode = !self.dark_mode;
                    let visuals = if self.dark_mode {
                        egui::Visuals::dark()
                    } else {
                        egui::Visuals::light()
                    };
                    ui.ctx().set_visuals(visuals);
                }
            });
        });
    }

    /// Copies the vault file to a user-chosen location.
    fn backup_vault(&mut self) {
        if !Vault::exists(&self.vault_path) {
            self.error = Some("There is no vault to back up.".into());
            return;
        }
        let Some(dest) = rfd::FileDialog::new()
            .set_file_name("vault.enc.backup")
            .save_file()
        else {
            return;
        };
        if let Err(e) = std::fs::copy(&self.vault_path, &dest) {
            self.error = Some(format!("Backup failed: {e}"));
        }
    }

    /// Copies the vault into the backup folder with a timestamped name. Updates
    /// `last_backup` up front so an auto-backup won't retry every frame on error.
    fn run_vault_backup(&mut self, manual: bool) {
        if !Vault::exists(&self.vault_path) {
            if manual {
                self.error = Some("There is no vault to back up.".into());
            }
            return;
        }
        let dir = self.settings.backup_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.error = Some(format!("Could not create backup folder: {e}"));
            return;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.settings.vault_backup.last_backup = Some(std::time::SystemTime::now());
        let _ = self.settings.save();
        let dest = dir.join(format!("vault-{stamp}.enc"));
        if let Err(e) = std::fs::copy(&self.vault_path, &dest) {
            self.error = Some(format!("Backup failed: {e}"));
        }
    }

    /// Renders the global settings page with a category rail on the left.
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        let mut hl_changed = false;
        let mut backup_now = false;
        let mut extras_action: Option<ExtrasAction> = None;

        // The category is selected in the left pane; show its content here.
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(8.0);
            match self.settings_category {
                SettingsCategory::General => self.settings_general(ui, &mut changed),
                SettingsCategory::Tabs => self.settings_tabs(ui, &mut changed),
                SettingsCategory::Vault => self.settings_vault(ui, &mut changed, &mut backup_now),
                SettingsCategory::Terminal => {
                    self.settings_terminal(ui, &mut changed, &mut hl_changed)
                }
                SettingsCategory::Extras => self.settings_extras(ui, &mut extras_action),
            }
        });

        if changed && let Err(e) = self.settings.save() {
            self.error = Some(format!("Could not save settings: {e:#}"));
        }
        if hl_changed {
            self.highlights.recompile();
            if let Err(e) = self.highlights.save() {
                self.error = Some(format!("Could not save highlights: {e:#}"));
            }
        }
        if backup_now {
            self.run_vault_backup(true);
        }
        match extras_action {
            Some(ExtrasAction::GrantLowPort) => {
                if let Some(cmd) = wazowski_servers::low_port_setcap_command() {
                    self.run_admin("Grant low-port permission".into(), cmd, None, true);
                }
                self.env_checks = None;
            }
            Some(ExtrasAction::InstallIperf) => {
                if let Some(cmd) = wazowski_servers::iperf_install_command() {
                    self.run_admin("Install iperf3".into(), cmd, None, false);
                }
                self.env_checks = None;
            }
            Some(ExtrasAction::Recheck) => self.env_checks = None,
            None => {}
        }
    }

    fn settings_general(&mut self, ui: &mut egui::Ui, changed: &mut bool) {
        if ui
            .checkbox(&mut self.settings.allow_multiple_instances, "Allow multiple instances")
            .on_hover_text("Takes effect at the next launch")
            .changed()
        {
            *changed = true;
        }
        let mut shell_on_startup = matches!(self.settings.startup_tab, StartupTab::LocalShell);
        if ui
            .checkbox(&mut shell_on_startup, "Open a local shell on startup")
            .changed()
        {
            self.settings.startup_tab =
                if shell_on_startup { StartupTab::LocalShell } else { StartupTab::None };
            *changed = true;
        }
        ui.horizontal(|ui| {
            ui.label("Open web GUI with:");
            egui::ComboBox::from_id_salt("web-scheme")
                .selected_text(self.settings.web_scheme.label())
                .show_ui(ui, |ui| {
                    for value in [WebScheme::Https, WebScheme::Http] {
                        if ui
                            .selectable_value(&mut self.settings.web_scheme, value, value.label())
                            .changed()
                        {
                            *changed = true;
                        }
                    }
                });
        })
        .response
        .on_hover_text("Scheme used by a session's right-click \"Open web GUI\" action");
    }

    fn settings_tabs(&mut self, ui: &mut egui::Ui, changed: &mut bool) {
        ui.horizontal(|ui| {
            ui.label("New tab opens:");
            let text = match self.settings.new_tab_placement {
                NewTabPlacement::Never => "At the far right",
                NewTabPlacement::WhenDuplicating => "Next to current when duplicating",
                NewTabPlacement::Always => "Always next to current",
            };
            egui::ComboBox::from_id_salt("new-tab-placement").selected_text(text).show_ui(ui, |ui| {
                for (value, label) in [
                    (NewTabPlacement::Never, "At the far right"),
                    (NewTabPlacement::WhenDuplicating, "Next to current when duplicating"),
                    (NewTabPlacement::Always, "Always next to current"),
                ] {
                    if ui
                        .selectable_value(&mut self.settings.new_tab_placement, value, label)
                        .changed()
                    {
                        *changed = true;
                    }
                }
            });
        });
    }

    fn settings_vault(&mut self, ui: &mut egui::Ui, changed: &mut bool, backup_now: &mut bool) {
        let vault_exists = Vault::exists(&self.vault_path);
        ui.label(RichText::new("Automatic vault backup").strong());
        if !vault_exists {
            ui.label(RichText::new("No vault exists yet.").weak());
        }
        if ui
            .checkbox(&mut self.settings.vault_backup.enabled, "Back up the vault automatically")
            .changed()
        {
            *changed = true;
        }
        ui.horizontal(|ui| {
            ui.label("Every");
            if ui
                .add(egui::DragValue::new(&mut self.settings.vault_backup.every_days).range(1..=365))
                .changed()
            {
                *changed = true;
            }
            ui.label("day(s)");
        });
        ui.horizontal(|ui| {
            ui.label("Folder:");
            ui.label(self.settings.backup_dir().display().to_string());
            if ui.button("Choose…").clicked()
                && let Some(dir) = rfd::FileDialog::new().pick_folder()
            {
                self.settings.vault_backup.dir = Some(dir);
                *changed = true;
            }
            if ui.button("Open directory").clicked() {
                let dir = self.settings.backup_dir();
                if let Err(e) = std::fs::create_dir_all(&dir).and_then(|()| open::that(&dir)) {
                    self.error = Some(format!("Could not open the backup folder: {e}"));
                }
            }
        });
        if let Some(when) = self.settings.vault_backup.last_backup {
            ui.label(RichText::new(format!("Last backup: {}", time_ago(when))).weak());
        }
        if ui.add_enabled(vault_exists, egui::Button::new("Back up now")).clicked() {
            *backup_now = true;
        }
    }

    fn settings_terminal(&mut self, ui: &mut egui::Ui, changed: &mut bool, hl_changed: &mut bool) {
        ui.horizontal(|ui| {
            ui.label("Default font size:");
            if ui
                .add(egui::DragValue::new(&mut self.settings.terminal_font_size).range(8.0..=40.0))
                .on_hover_text("Also: Ctrl+scroll in a terminal, or Ctrl+= / Ctrl+- / Ctrl+0")
                .changed()
            {
                *changed = true;
            }
            ui.label("pt");
        });

        ui.add_space(10.0);
        ui.label(RichText::new("Highlights").strong());
        ui.label(
            RichText::new("Regex patterns colored in terminal output. Toggle, recolor, or edit any rule.")
                .weak(),
        );
        let mut remove: Option<usize> = None;
        for (i, rule) in self.highlights.rules.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut rule.enabled, "")
                    .on_hover_text("Enable or disable this highlight rule")
                    .changed()
                {
                    *hl_changed = true;
                }
                if ui.button("✕").on_hover_text("Delete rule").clicked() {
                    remove = Some(i);
                }
                if ui.color_edit_button_srgb(&mut rule.color).changed() {
                    *hl_changed = true;
                }
                let valid = HighlightStore::is_valid(&rule.pattern);
                let edit = egui::TextEdit::singleline(&mut rule.pattern)
                    .desired_width(ui.available_width())
                    .hint_text("regex, e.g. .*error.*")
                    .text_color_opt((!valid).then_some(Color32::from_rgb(230, 80, 80)));
                if ui.add(edit).on_hover_text("Regex pattern (red text = invalid)").changed() {
                    *hl_changed = true;
                }
            });
        }
        ui.horizontal(|ui| {
            if ui.button("Add rule").clicked() {
                self.highlights.rules.push(HighlightRule {
                    pattern: String::new(),
                    color: [200, 200, 120],
                    enabled: true,
                });
                *hl_changed = true;
            }
            if ui
                .button("Restore defaults")
                .on_hover_text("Replace with the built-in rules")
                .clicked()
            {
                self.highlights.rules = crate::highlights::default_rules();
                *hl_changed = true;
            }
        });
        if let Some(i) = remove {
            self.highlights.rules.remove(i);
            *hl_changed = true;
        }
    }

    fn settings_extras(&mut self, ui: &mut egui::Ui, action: &mut Option<ExtrasAction>) {
        if self.env_checks.is_none() {
            self.env_checks = Some(compute_env_checks());
        }
        let checks = self.env_checks.clone().unwrap_or_default();
        ui.label(RichText::new("Environment").strong());
        ui.label(RichText::new("Checks for optional tools and permissions Wazowski can use.").weak());
        ui.add_space(6.0);

        let status = |ui: &mut egui::Ui, label: &str, ok: bool| {
            let (mark, color) = if ok {
                ("✔", Color32::from_rgb(120, 200, 120))
            } else {
                ("✘", Color32::from_rgb(230, 120, 120))
            };
            ui.label(RichText::new(mark).color(color));
            ui.label(label);
        };

        egui::Grid::new("extras-checks").num_columns(3).spacing([8.0, 6.0]).show(ui, |ui| {
            // Low-port permission (Linux).
            if let Some(granted) = checks.low_port {
                status(ui, "Low-port permission (bind < 1024)", granted);
                if !granted
                    && wazowski_servers::low_port_setcap_command().is_some()
                    && ui.button("Grant").clicked()
                {
                    *action = Some(ExtrasAction::GrantLowPort);
                } else {
                    ui.label("");
                }
                ui.end_row();
            }
            // iperf3.
            status(ui, "iperf3 (bandwidth server)", checks.iperf3);
            if !checks.iperf3
                && wazowski_servers::iperf_install_command().is_some()
                && ui.button("Install").clicked()
            {
                *action = Some(ExtrasAction::InstallIperf);
            } else {
                ui.label("");
            }
            ui.end_row();
            // Printing.
            status(ui, "Printing service (lp / lpr)", checks.printing);
            if checks.printing {
                ui.label("");
            } else {
                ui.label(RichText::new("install CUPS to enable Print output").weak());
            }
            ui.end_row();
            // RDP client (for launching saved RDP sessions).
            status(ui, "RDP client", checks.rdp_client.is_some());
            match &checks.rdp_client {
                Some(name) => ui.label(RichText::new(format!("found: {name}")).weak()),
                None => ui.label(
                    RichText::new(format!("install one of: {}", RDP_CLIENTS.join(", "))).weak(),
                ),
            };
            ui.end_row();
            // Default web browser (used by "Open web GUI").
            status(ui, "Default web browser", checks.default_browser.is_some());
            match &checks.default_browser {
                Some(name) => ui.label(RichText::new(name.as_str()).weak()),
                None => ui.label(RichText::new("could not determine").weak()),
            };
            ui.end_row();
        });

        ui.add_space(6.0);
        if ui.button("Re-check").clicked() {
            *action = Some(ExtrasAction::Recheck);
        }
    }

    /// Deletes the vault file and any saved key, after confirmation.
    fn delete_vault(&mut self) {
        let _ = Vault::disable_keyring_unlock();
        if let Err(e) = std::fs::remove_file(&self.vault_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            self.error = Some(format!("Could not delete the vault: {e}"));
            return;
        }
        self.vault = VaultState::Absent;
        self.dialog = Dialog::None;
    }

    fn sidebar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(4.0);
        // A vertical icon rail to switch views, beside the view's content.
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                let view = &mut self.sidebar_view;
                const SIZE: f32 = 26.0;
                let icon = |glyph: &str, color: Color32| {
                    RichText::new(glyph).size(SIZE).color(color)
                };
                ui.selectable_value(
                    view,
                    SidebarView::Sessions,
                    icon("🖥", Color32::from_rgb(90, 170, 255)),
                )
                .on_hover_text("Sessions");
                ui.selectable_value(
                    view,
                    SidebarView::Macros,
                    icon("📜", Color32::from_rgb(240, 170, 60)),
                )
                .on_hover_text("Macros");
                ui.selectable_value(
                    view,
                    SidebarView::Files,
                    icon("📁", Color32::from_rgb(120, 200, 120)),
                )
                .on_hover_text("Files (SFTP)");
                ui.selectable_value(
                    view,
                    SidebarView::Settings,
                    icon("⚙", Color32::from_rgb(170, 170, 180)),
                )
                .on_hover_text("Settings");
            });
            ui.separator();
            ui.vertical(|ui| match self.sidebar_view {
                SidebarView::Sessions => self.sidebar_sessions(ui, ctx),
                SidebarView::Macros => self.sidebar_macros(ui),
                SidebarView::Files => self.sidebar_files(ui, ctx),
                SidebarView::Settings => self.sidebar_settings_categories(ui),
            });
        });
    }

    /// The Settings view's left pane: the category selector.
    fn sidebar_settings_categories(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();
        for (cat, label) in [
            (SettingsCategory::General, "General"),
            (SettingsCategory::Tabs, "Tabs"),
            (SettingsCategory::Vault, "Vault"),
            (SettingsCategory::Terminal, "Terminal"),
            (SettingsCategory::Extras, "Extras"),
        ] {
            ui.selectable_value(&mut self.settings_category, cat, label);
        }
    }

    /// The Files view: the SFTP browser for the active single-pane SSH tab.
    fn sidebar_files(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let single_pane = matches!(
            self.tabs.get(self.active).map(|t| &t.content),
            Some(TabContent::Terminal(p)) if p.count() == 1
        );
        if single_pane
            && let Some(tab) = self.tabs.get_mut(self.active)
            && let Some(files) = &mut tab.files
        {
            files.ui(ui, ctx);
        } else {
            ui.add_space(8.0);
            ui.label(
                RichText::new("Open an SSH session (unsplit) to browse its files here.").weak(),
            );
        }
    }

    fn sidebar_sessions(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading("Sessions");
            if ui.small_button("+").on_hover_text("New session").clicked() {
                self.dialog = Dialog::EditSession(SessionForm::new());
            }
        });

        match &self.vault {
            VaultState::Locked => {
                if ui.button("🔒 Unlock vault").clicked() {
                    self.dialog = Dialog::UnlockVault { password: String::new(), remember: false, error: None };
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

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            self.session_tree(ui, ctx);
        });
    }

    /// The Macros view: a list of macros to run (double-click) or manage.
    fn sidebar_macros(&mut self, ui: &mut egui::Ui) {
        enum Act {
            Run(usize, MacroTarget),
            Edit(usize),
            Duplicate(usize),
            Delete(usize),
            New,
        }
        let mut act = None;
        ui.horizontal(|ui| {
            ui.heading("Macros");
            if ui.small_button("+").on_hover_text("New macro").clicked() {
                act = Some(Act::New);
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if self.macros.macros.is_empty() {
                ui.label(RichText::new("No macros yet. Click + to add one.").weak());
            }
            for (i, m) in self.macros.macros.iter().enumerate() {
                let resp = ui.selectable_label(false, format!("⚙ {}", m.name));
                if resp.double_clicked() {
                    act = Some(Act::Run(i, MacroTarget::ActivePane));
                }
                resp.on_hover_text("Double-click to run on the active terminal; right-click for more")
                    .context_menu(|ui| {
                        if ui.button("Run on active terminal").clicked() {
                            act = Some(Act::Run(i, MacroTarget::ActivePane));
                            ui.close();
                        }
                        if ui.button("Run on this tab's panes").clicked() {
                            act = Some(Act::Run(i, MacroTarget::TabPanes));
                            ui.close();
                        }
                        if ui.button("Run on all terminals").clicked() {
                            act = Some(Act::Run(i, MacroTarget::AllTerminals));
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Edit…").clicked() {
                            act = Some(Act::Edit(i));
                            ui.close();
                        }
                        if ui.button("Duplicate").clicked() {
                            act = Some(Act::Duplicate(i));
                            ui.close();
                        }
                        if ui.button("Delete").clicked() {
                            act = Some(Act::Delete(i));
                            ui.close();
                        }
                    });
            }
        });
        match act {
            Some(Act::Run(i, target)) => self.dialog = Dialog::ConfirmMacro { index: i, target },
            Some(Act::Edit(i)) => {
                let m = &self.macros.macros[i];
                self.dialog = Dialog::MacroEdit(MacroForm {
                    index: Some(i),
                    name: m.name.clone(),
                    steps: m.steps.clone(),
                    error: None,
                });
            }
            Some(Act::Duplicate(i)) => {
                let mut copy = self.macros.macros[i].clone();
                copy.name = format!("{} copy", copy.name);
                self.macros.macros.push(copy);
                self.save_macros();
            }
            Some(Act::Delete(i)) => {
                self.macros.macros.remove(i);
                self.save_macros();
            }
            Some(Act::New) => {
                self.dialog = Dialog::MacroEdit(MacroForm {
                    index: None,
                    name: String::new(),
                    steps: Vec::new(),
                    error: None,
                });
            }
            None => {}
        }
    }

    fn session_tree(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mut action: Option<TreeAction> = None;
        let mut open_serial: Option<String> = None;

        // Destinations for move/copy: the local store plus every reachable share.
        let mut destinations = vec![Destination {
            store: StoreId::Local,
            label: "Local".into(),
            folders: self.sessions.folders(),
        }];
        for source in &self.shared {
            if source.available() {
                destinations.push(Destination {
                    store: StoreId::Shared(source.id().to_owned()),
                    label: source.name().to_owned(),
                    folders: source.store().folders(),
                });
            }
        }

        // Local sessions.
        render_store(ui, &StoreId::Local, &self.sessions, true, &destinations, &mut action);

        // Each shared source as its own collapsible section.
        for source in &self.shared {
            let badge = if source.available() { "" } else { "  (offline)" };
            let def = source.def();
            let icon = if def.icon.is_empty() { "🌐" } else { def.icon.as_str() };
            let title = {
                let t = RichText::new(format!("{icon} {}{badge}", source.name()));
                match def.color {
                    Some([r, g, b]) => t.color(Color32::from_rgb(r, g, b)),
                    None => t,
                }
            };
            let header = egui::CollapsingHeader::new(title)
                .id_salt(("shared-source", source.id()))
                .default_open(true);
            let store = StoreId::Shared(source.id().to_owned());
            let editable = source.available();
            let resp = header.show(ui, |ui| {
                if let Some(note) = source.status() {
                    ui.label(RichText::new(format!("⚠ {note}")).color(ui.visuals().warn_fg_color));
                }
                render_store(ui, &store, source.store(), editable, &destinations, &mut action);
            });
            delayed_tooltip(ui, &resp.header_response, &source_hint(source.def()));
            // Dropping onto the source header targets that store's root.
            if editable
                && let Some(payload) = resp.header_response.dnd_release_payload::<DragPayload>()
            {
                action = Some(TreeAction::Dropped {
                    payload: (*payload).clone(),
                    to: store.clone(),
                    folder: String::new(),
                });
            }
            let open_label = match source.def().kind {
                SourceKind::Folder => "Open file location",
                SourceKind::Git => "Open repository in browser",
            };
            resp.header_response.context_menu(|ui| {
                if ui.button("Sync now").clicked() {
                    action = Some(TreeAction::SyncSource(source.id().to_owned()));
                    ui.close();
                }
                if ui.button(open_label).clicked() {
                    action = Some(TreeAction::OpenSource(source.id().to_owned()));
                    ui.close();
                }
                if editable {
                    if ui.button("New session here").clicked() {
                        action = Some(TreeAction::NewSessionIn(store.clone(), String::new()));
                        ui.close();
                    }
                    if ui.button("New folder").clicked() {
                        action = Some(TreeAction::NewFolderIn(store.clone(), String::new()));
                        ui.close();
                    }
                }
                ui.separator();
                if ui.button("Edit source…").clicked() {
                    action = Some(TreeAction::EditSource(source.id().to_owned()));
                    ui.close();
                }
                if ui.button("Remove source").clicked() {
                    action = Some(TreeAction::RemoveSource(source.id().to_owned()));
                    ui.close();
                }
            });
        }

        // Detected serial devices, always below everything else. Collapsed by
        // default; grouped by kind; double-click a device to open a connection.
        egui::CollapsingHeader::new("🔌 Serial connections")
            .id_salt("serial-devices")
            .default_open(false)
            .show(ui, |ui| {
                if self.serial_ports.is_empty() {
                    ui.label(RichText::new("No serial devices detected.").weak());
                }
                for kind in [SerialKind::Usb, SerialKind::Bluetooth, SerialKind::Pci, SerialKind::Other]
                {
                    let group: Vec<&SerialDevice> =
                        self.serial_ports.iter().filter(|d| d.kind == kind).collect();
                    if group.is_empty() {
                        continue;
                    }
                    egui::CollapsingHeader::new(kind.label())
                        .id_salt(("serial-kind", kind.label()))
                        .default_open(false)
                        .show(ui, |ui| {
                            for dev in group {
                                let short = dev.name.rsplit(['/', '\\']).next().unwrap_or(&dev.name);
                                let resp = ui.selectable_label(false, format!("🔌 {short}"));
                                delayed_tooltip(ui, &resp, &dev.name);
                                if resp.double_clicked() {
                                    open_serial = Some(dev.name.clone());
                                }
                            }
                        });
                }
            });

        // Fill the remaining blank space as a drop zone + right-click menu for
        // the local store, so the whole empty pane is usable.
        let bg = ui.allocate_response(ui.available_size(), egui::Sense::click());
        if let Some(payload) = bg.dnd_release_payload::<DragPayload>() {
            action = Some(TreeAction::Dropped {
                payload: (*payload).clone(),
                to: StoreId::Local,
                folder: String::new(),
            });
        }
        let mut add_source = false;
        bg.context_menu(|ui| {
            if ui.button("New session").clicked() {
                action = Some(TreeAction::NewSessionIn(StoreId::Local, String::new()));
                ui.close();
            }
            if ui.button("New folder").clicked() {
                action = Some(TreeAction::NewFolderIn(StoreId::Local, String::new()));
                ui.close();
            }
            ui.separator();
            if ui.button("Add shared source…").clicked() {
                add_source = true;
                ui.close();
            }
        });
        if add_source {
            self.dialog = Dialog::AddSource(AddSourceForm::default());
        }
        if let Some(port) = open_serial {
            let mut form = SerialForm::new();
            form.path = port;
            form.locked_port = true;
            self.dialog = Dialog::SerialConnect(form);
        }

        self.apply_tree_action(action, ctx);
    }

    fn apply_tree_action(&mut self, action: Option<TreeAction>, ctx: &egui::Context) {
        let Some(action) = action else { return };
        let result = match action {
            TreeAction::Connect(store, id) => {
                if let Some(session) = self.session_in(&store, &id) {
                    self.remember_recent(&id);
                    self.start_connect(&session, ctx);
                }
                Ok(())
            }
            TreeAction::ConnectAs(store, id) => {
                if let Some(session) = self.session_in(&store, &id) {
                    self.connect_as(&session);
                }
                Ok(())
            }
            TreeAction::OpenWebGui(store, id) => {
                if let Some(session) = self.session_in(&store, &id) {
                    let url = web_gui_url(&session.host, self.settings.web_scheme);
                    open::that_detached(&url)
                        .map_err(|e| anyhow::anyhow!("could not open the browser: {e}"))
                } else {
                    Ok(())
                }
            }
            TreeAction::NetworkTool(store, id, tool) => {
                if let Some(session) = self.session_in(&store, &id) {
                    self.session_network_tool(&session.host, tool);
                }
                Ok(())
            }
            TreeAction::Edit(store, id) => {
                if let Some(session) = self.session_in(&store, &id) {
                    let mut form = SessionForm::from_session(&session);
                    form.target = store;
                    self.dialog = Dialog::EditSession(form);
                }
                Ok(())
            }
            TreeAction::Delete(store, id) => self.store_remove(&store, &id),
            TreeAction::Duplicate(store, id) => {
                if let Some(original) = self.session_in(&store, &id) {
                    let mut copy = original.clone();
                    copy.id = Session::new("", "", "").id; // fresh id
                    copy.name = format!("{} copy", original.name);
                    self.store_upsert(&store, copy)
                } else {
                    Ok(())
                }
            }
            TreeAction::MoveTo { from, id, to, folder } => {
                if from == to {
                    self.store_move(&from, &id, &folder)
                } else if let Some(mut session) = self.session_in(&from, &id) {
                    session.folder = folder;
                    self.store_upsert(&to, session).and_then(|()| self.store_remove(&from, &id))
                } else {
                    Ok(())
                }
            }
            TreeAction::CopyTo { from, id, to, folder } => {
                if let Some(original) = self.session_in(&from, &id) {
                    let mut copy = original.clone();
                    copy.id = Session::new("", "", "").id; // fresh id so it's independent
                    copy.folder = folder;
                    self.store_upsert(&to, copy)
                } else {
                    Ok(())
                }
            }
            TreeAction::MoveFolder { from, folder, to, parent } => {
                self.transfer_folder(&from, &folder, &to, &parent, false)
            }
            TreeAction::CopyFolder { from, folder, to, parent } => {
                self.transfer_folder(&from, &folder, &to, &parent, true)
            }
            TreeAction::NewSessionIn(store, folder) => {
                let mut form = SessionForm::new();
                form.folder = folder;
                form.target = store;
                self.dialog = Dialog::EditSession(form);
                Ok(())
            }
            TreeAction::NewFolderIn(store, parent) => {
                self.dialog = Dialog::NewFolder { target: store, parent, name: String::new() };
                Ok(())
            }
            TreeAction::RenameFolder(store, name) => {
                self.dialog =
                    Dialog::RenameFolder { target: store, old: name.clone(), name };
                Ok(())
            }
            TreeAction::FolderAppearance(store, folder) => {
                let style = self.store_folder_style(&store, &folder);
                self.dialog = Dialog::FolderAppearance {
                    target: store,
                    folder,
                    icon: style.as_ref().map(|s| s.icon.clone()).unwrap_or_default(),
                    color: style.and_then(|s| s.color),
                };
                Ok(())
            }
            TreeAction::DeleteFolder(store, name) => self.store_remove_folder(&store, &name),
            TreeAction::SyncSource(id) => {
                if let Some(source) = self.shared.iter_mut().find(|s| s.id() == id) {
                    source.reload();
                    if !source.available() {
                        self.dialog = Dialog::MissingShare { id };
                    }
                }
                Ok(())
            }
            TreeAction::OpenSource(id) => {
                if let Some(source) = self.shared.iter().find(|s| s.id() == id) {
                    sources::open_source(source.def())
                } else {
                    Ok(())
                }
            }
            TreeAction::EditSource(id) => {
                if let Some(source) = self.shared.iter().find(|s| s.id() == id) {
                    let def = source.def().clone();
                    let token = if def.auth == GitAuthKind::Https {
                        sources::load_git_token(&def.id)
                    } else {
                        None
                    };
                    self.dialog = Dialog::AddSource(AddSourceForm::from_def(&def, token));
                }
                Ok(())
            }
            TreeAction::RemoveSource(id) => self.remove_source(&id),
            TreeAction::Dropped { payload, to, folder } => {
                // Ignore no-op or invalid drops; otherwise ask Move or Copy.
                if is_noop_drop(&payload, &to, &folder) {
                    Ok(())
                } else {
                    self.dialog = Dialog::DropMenu { payload, to, folder };
                    Ok(())
                }
            }
        };
        if let Err(e) = result {
            self.error = Some(format!("{e:#}"));
        }
    }

    // --- Store routing ------------------------------------------------------

    fn shared_mut(&mut self, id: &str) -> Option<&mut SharedSource> {
        self.shared.iter_mut().find(|s| s.id() == id)
    }

    /// A read-only reference to the given store.
    fn store_ref(&self, store: &StoreId) -> Option<&SessionStore> {
        match store {
            StoreId::Local => Some(&self.sessions),
            StoreId::Shared(id) => self.shared.iter().find(|s| s.id() == id).map(|s| s.store()),
        }
    }

    /// Moves or copies a folder (with all its subfolders and sessions) to a new
    /// parent, possibly in a different store.
    fn transfer_folder(
        &mut self,
        from: &StoreId,
        folder: &str,
        to: &StoreId,
        parent: &str,
        copy: bool,
    ) -> anyhow::Result<()> {
        let base = folder.rsplit('/').next().unwrap_or(folder);
        let new_base = if parent.is_empty() { base.to_owned() } else { format!("{parent}/{base}") };
        if new_base == folder && from == to {
            return Ok(()); // no-op
        }
        // Can't move a folder into itself or its own subtree (same store).
        if !copy && from == to && (new_base == folder || new_base.starts_with(&format!("{folder}/")))
        {
            anyhow::bail!("can't move a folder into itself");
        }
        let prefix = format!("{folder}/");
        let repath = |f: &str| -> String {
            if f == folder {
                new_base.clone()
            } else if let Some(rest) = f.strip_prefix(&prefix) {
                format!("{new_base}/{rest}")
            } else {
                f.to_owned()
            }
        };

        // Same-store move is just a re-path (handles subtree + collisions).
        if !copy && from == to {
            return self.store_rename_folder(from, folder, &new_base);
        }

        // Snapshot the subtree from the source.
        let src = self.store_ref(from).ok_or_else(|| anyhow::anyhow!("source is gone"))?;
        let folders: Vec<String> =
            src.folders().into_iter().filter(|f| f == folder || f.starts_with(&prefix)).collect();
        let sessions: Vec<Session> = src
            .all()
            .iter()
            .filter(|s| s.folder == folder || s.folder.starts_with(&prefix))
            .cloned()
            .collect();

        // Recreate in the destination.
        self.store_add_folder(to, &new_base)?;
        for f in &folders {
            self.store_add_folder(to, &repath(f))?;
        }
        for session in &sessions {
            let mut moved = session.clone();
            if copy {
                moved.id = Session::new("", "", "").id;
            }
            moved.folder = repath(&session.folder);
            self.store_upsert(to, moved)?;
        }

        // For a move, remove the originals.
        if !copy {
            for session in &sessions {
                self.store_remove(from, &session.id)?;
            }
            self.store_remove_folder(from, folder)?;
        }
        Ok(())
    }

    /// Records a recently connected session and persists the change.
    fn remember_recent(&mut self, id: &str) {
        self.settings.remember_recent(id);
        let _ = self.settings.save();
    }

    /// Finds a session by id in the local store or any shared source.
    fn find_session_anywhere(&self, id: &str) -> Option<(StoreId, Session)> {
        if let Some(s) = self.sessions.get(id) {
            return Some((StoreId::Local, s.clone()));
        }
        for source in &self.shared {
            if let Some(s) = source.store().get(id) {
                return Some((StoreId::Shared(source.id().to_owned()), s.clone()));
            }
        }
        None
    }

    /// The recent sessions that still exist, as (store, id, name), newest first.
    fn recent_sessions(&self) -> Vec<(StoreId, String, String)> {
        self.settings
            .recent
            .iter()
            .filter_map(|id| {
                self.find_session_anywhere(id).map(|(store, s)| (store, id.clone(), s.name))
            })
            .collect()
    }

    /// A cloned session from the given store.
    fn session_in(&self, store: &StoreId, id: &str) -> Option<Session> {
        match store {
            StoreId::Local => self.sessions.get(id).cloned(),
            StoreId::Shared(sid) => {
                self.shared.iter().find(|s| s.id() == sid).and_then(|s| s.store().get(id).cloned())
            }
        }
    }

    fn store_upsert(&mut self, store: &StoreId, session: Session) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.upsert(session),
            StoreId::Shared(id) => self.offline_guard(id)?.upsert(session),
        }
    }

    fn store_remove(&mut self, store: &StoreId, id: &str) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.remove(id).map(|_| ()),
            StoreId::Shared(sid) => self.offline_guard(sid)?.remove(id),
        }
    }

    fn store_move(&mut self, store: &StoreId, id: &str, folder: &str) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.move_to_folder(id, folder),
            StoreId::Shared(sid) => self.offline_guard(sid)?.move_to_folder(id, folder),
        }
    }

    fn store_add_folder(&mut self, store: &StoreId, name: &str) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.add_folder(name).map(|_| ()),
            StoreId::Shared(sid) => self.offline_guard(sid)?.add_folder(name),
        }
    }

    fn store_rename_folder(&mut self, store: &StoreId, old: &str, new: &str) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.rename_folder(old, new),
            StoreId::Shared(sid) => self.offline_guard(sid)?.rename_folder(old, new),
        }
    }

    fn store_remove_folder(&mut self, store: &StoreId, name: &str) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.remove_folder(name),
            StoreId::Shared(sid) => self.offline_guard(sid)?.remove_folder(name),
        }
    }

    fn store_folder_style(&self, store: &StoreId, folder: &str) -> Option<FolderStyle> {
        match store {
            StoreId::Local => self.sessions.folder_style(folder).cloned(),
            StoreId::Shared(sid) => {
                self.shared.iter().find(|s| s.id() == sid)?.store().folder_style(folder).cloned()
            }
        }
    }

    fn store_set_folder_style(
        &mut self,
        store: &StoreId,
        folder: &str,
        style: FolderStyle,
    ) -> anyhow::Result<()> {
        match store {
            StoreId::Local => self.sessions.set_folder_style(folder, style),
            StoreId::Shared(sid) => self.offline_guard(sid)?.set_folder_style(folder, style),
        }
    }

    /// Returns the shared source for writing, or an error if it is offline.
    fn offline_guard(&mut self, id: &str) -> anyhow::Result<&mut SharedSource> {
        let source = self
            .shared_mut(id)
            .ok_or_else(|| anyhow::anyhow!("that shared source is gone"))?;
        if !source.available() {
            anyhow::bail!("the share is offline; changes are disabled until it is reachable");
        }
        Ok(source)
    }

    fn remove_source(&mut self, id: &str) -> anyhow::Result<()> {
        self.sources_config.remove(id)?;
        self.shared.retain(|s| s.id() != id);
        sources::delete_git_token(id);
        Ok(())
    }

    fn tab_strip(&mut self, ui: &mut egui::Ui) {
        let mut close = None;
        let mut pane_action: Option<SplitButton> = None;
        let mut baud_delta: Option<i32> = None;
        let mut tab_action: Option<TabAct> = None;
        // Precompute everything the two Sides closures read, so neither needs to
        // borrow `self` (Sides takes both closures at once).
        let active = self.active;
        let tab_count = self.tabs.len();
        let hints: Vec<String> = self.tabs.iter().map(|t| self.tab_hint(t)).collect();
        let labels: Vec<String> = self
            .tabs
            .iter()
            .map(|tab| {
                let name: String = tab.label.chars().take(28).collect();
                match &tab.content {
                    TabContent::Connecting(c) if c.error.is_some() => format!("⚠ {name}"),
                    TabContent::Connecting(_) => format!("⏳ {name}"),
                    TabContent::Terminal(_) => name,
                    TabContent::Servers | TabContent::Network => format!("🖧 {name}"),
                    TabContent::Detached { .. } => format!("⇄ {name}"),
                }
            })
            .collect();
        let serial_baud = self.active_serial_baud();
        let (show_split, can_close_pane) = match self.tabs.get(self.active).map(|t| &t.content) {
            Some(TabContent::Terminal(p)) => (true, p.count() > 1),
            _ => (false, false),
        };
        let mut broadcast = self.broadcast;
        let mut clicked_tab = None;
        let mut new_shell = false;

        egui::containers::Sides::new().shrink_left().spacing(6.0).show(
            ui,
            |ui| {
                // A solid (non-floating) bar that shows when the tabs overflow,
                // drawn under the tabs rather than over them.
                ui.style_mut().spacing.scroll = egui::style::ScrollStyle::solid();
                egui::ScrollArea::horizontal()
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for (i, label) in labels.iter().enumerate() {
                                let resp = ui.selectable_label(i == active, label);
                                if resp.clicked() {
                                    clicked_tab = Some(i);
                                }
                                delayed_tooltip(ui, &resp, &hints[i]);
                                resp.context_menu(|ui| {
                                    if ui.button("Duplicate").clicked() {
                                        tab_action = Some(TabAct::Duplicate(i));
                                        ui.close();
                                    }
                                    if ui.button("Close").clicked() {
                                        close = Some(i);
                                        ui.close();
                                    }
                                    if tab_count > 1 && ui.button("Close others").clicked() {
                                        tab_action = Some(TabAct::CloseOthers(i));
                                        ui.close();
                                    }
                                });
                                if ui.small_button("×").on_hover_text("Close tab").clicked() {
                                    close = Some(i);
                                }
                                ui.separator();
                            }
                            // New-tab button at the end of the tab list.
                            if ui
                                .button("+")
                                .on_hover_text("New local shell (Ctrl+Shift+T)")
                                .clicked()
                            {
                                new_shell = true;
                            }
                        });
                    });
            },
            |ui| {
                // Sides adds right widgets right-to-left, so add in reverse order.
                if let Some(baud) = serial_baud {
                    if ui.button("+").on_hover_text("Raise baud (Ctrl+Shift+Up)").clicked() {
                        baud_delta = Some(1);
                    }
                    ui.label(format!("{baud} baud"));
                    if ui.button("−").on_hover_text("Lower baud (Ctrl+Shift+Down)").clicked() {
                        baud_delta = Some(-1);
                    }
                    ui.separator();
                }
                if show_split {
                    if can_close_pane
                        && ui.button("⊟").on_hover_text("Close focused pane").clicked()
                    {
                        pane_action = Some(SplitButton::Close);
                    }
                    if ui.button("⇩").on_hover_text("Split pane down").clicked() {
                        pane_action = Some(SplitButton::Split(SplitDir::Vertical));
                    }
                    if ui.button("⇥").on_hover_text("Split pane right").clicked() {
                        pane_action = Some(SplitButton::Split(SplitDir::Horizontal));
                    }
                }
                // Broadcast is a plain button that shows its on/off state, so it
                // looks the same as the split buttons.
                if ui
                    .add(egui::Button::new("⇉").selected(broadcast))
                    .on_hover_text("Broadcast (multi-exec): send typing to every terminal")
                    .clicked()
                {
                    broadcast = !broadcast;
                }
            },
        );
        self.broadcast = broadcast;
        if let Some(i) = clicked_tab {
            self.active = i;
            // Leave the Settings view so the clicked tab is shown.
            if self.sidebar_view == SidebarView::Settings {
                self.sidebar_view = SidebarView::Sessions;
            }
        }
        if new_shell {
            if self.sidebar_view == SidebarView::Settings {
                self.sidebar_view = SidebarView::Sessions;
            }
            self.open_local_shell(ui.ctx());
        }
        match pane_action {
            Some(SplitButton::Split(dir)) => self.split_active_pane(dir, ui.ctx()),
            Some(SplitButton::Close) => self.close_active_pane(),
            None => {}
        }
        if let Some(delta) = baud_delta {
            self.adjust_baud(delta);
        }
        match tab_action {
            Some(TabAct::Duplicate(i)) => {
                let ctx = ui.ctx().clone();
                self.duplicate_tab(i, &ctx);
            }
            Some(TabAct::CloseOthers(i)) => {
                let keep_id = self.tabs[i].id;
                let mut j = 0;
                while j < self.tabs.len() {
                    if self.tabs[j].id != keep_id {
                        self.close_tab(j);
                    } else {
                        j += 1;
                    }
                }
            }
            None => {}
        }
        if let Some(i) = close {
            self.close_tab(i);
        }
    }

    fn central(&mut self, ui: &mut egui::Ui) {
        // The Settings view (selected in the left rail) replaces the terminal area.
        if self.sidebar_view == SidebarView::Settings {
            self.render_settings(ui);
            return;
        }
        // The servers manager needs other &mut self fields, so handle it before
        // the &mut self.tabs borrow below.
        match self.tabs.get(self.active).map(|t| &t.content) {
            Some(TabContent::Servers) => {
                self.render_servers(ui);
                return;
            }
            Some(TabContent::Network) => {
                self.render_network(ui);
                return;
            }
            Some(TabContent::Terminal(panes)) if panes.all_exited() => {
                self.render_ended_tab(ui);
                return;
            }
            Some(TabContent::Detached { host_tab }) => {
                let host = *host_tab;
                self.render_detached_tab(ui, host);
                return;
            }
            _ => {}
        }

        // The find-in-terminals bar sits above the terminal area.
        if self.find.is_some() {
            self.render_find_bar(ui);
        }

        // A terminal shouldn't take keystrokes while a modal dialog is open.
        let interactive = matches!(self.dialog, Dialog::None);
        // Collect retry/copy actions to apply after the borrow ends.
        let mut retry = None;
        let active = self.active;
        let broadcast = self.broadcast;
        let search = self
            .find
            .as_ref()
            .filter(|f| !f.query.is_empty())
            .map(|f| SearchQuery { needle: f.query.clone(), case_sensitive: f.case_sensitive });
        let mut broadcast_src: Option<(u64, Vec<u8>)> = None;
        let mut connect_recent: Option<(StoreId, String)> = None;
        let recents = self.recent_sessions();
        // Sessions that can be moved into a split pane: other single-terminal tabs.
        let targets: Vec<SwapTarget> = self
            .tabs
            .iter()
            .enumerate()
            .filter(|(i, t)| {
                *i != active
                    && matches!(&t.content, TabContent::Terminal(p) if p.count() == 1 && !p.all_exited())
            })
            .map(|(_, t)| SwapTarget { tab_id: t.id, label: t.label.clone() })
            .collect();
        let mut pane_action: Option<PaneAction> = None;
        let font_size =
            self.tabs.get(active).map(|t| t.font_size).unwrap_or(self.settings.terminal_font_size);
        let highlights = self.highlights.compiled();
        match self.tabs.get_mut(active) {
            Some(tab) => match &mut tab.content {
                TabContent::Terminal(panes) => {
                    let origin = tab.origin_term;
                    broadcast_src = panes.show(
                        ui,
                        interactive,
                        broadcast,
                        search.as_ref(),
                        &targets,
                        origin,
                        font_size,
                        highlights,
                        &mut pane_action,
                    );
                }
                TabContent::Connecting(c) => {
                    if let Some(action) = connecting_view(ui, c, tab.id) {
                        retry = Some(action);
                    }
                }
                TabContent::Servers | TabContent::Network | TabContent::Detached { .. } => {}
            },
            None => {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() / 4.0);
                    ui.heading("Wazowski");
                    ui.add_space(8.0);
                    ui.label(RichText::new("Double-click a session, or open a local shell.").weak());
                    ui.add_space(8.0);
                    if ui.button("New local shell").clicked() {
                        self.open_local_shell(ui.ctx());
                    }
                    if !recents.is_empty() {
                        ui.add_space(16.0);
                        ui.label(RichText::new("Resume a recent session").strong());
                        ui.add_space(4.0);
                        for (store, id, name) in &recents {
                            if ui.button(format!("🖥 {name}")).clicked() {
                                connect_recent = Some((store.clone(), id.clone()));
                            }
                        }
                    }
                });
            }
        }
        if let Some((store, id)) = connect_recent
            && let Some(session) = self.session_in(&store, &id)
        {
            let ctx = ui.ctx().clone();
            self.remember_recent(&id);
            self.start_connect(&session, &ctx);
        }
        if let Some(tab_id) = retry {
            let ctx = ui.ctx().clone();
            self.retry_tab(tab_id, &ctx);
        }
        if let Some(action) = pane_action {
            let ctx = ui.ctx().clone();
            self.handle_pane_action(action, &ctx);
        }
        // Ctrl+scroll on the active terminal adjusts the global font size.
        let zoom = match self.tabs.get_mut(active).map(|t| &mut t.content) {
            Some(TabContent::Terminal(panes)) => {
                let focused = panes.focused_id();
                panes.get_mut(focused).map(|t| t.take_zoom()).unwrap_or(0.0)
            }
            _ => 0.0,
        };
        if zoom != 0.0 {
            self.nudge_active_font_size(zoom.signum());
        }
        // Multi-exec: mirror the focused pane's input to every other terminal
        // that isn't the source and hasn't been excluded from broadcast.
        if broadcast
            && let Some((src_id, bytes)) = broadcast_src
            && !bytes.is_empty()
        {
            for tab in self.tabs.iter_mut() {
                if let TabContent::Terminal(panes) = &mut tab.content {
                    panes.for_each(|t| {
                        if t.id() != src_id && !t.broadcast_excluded() {
                            t.write(&bytes);
                        }
                    });
                }
            }
        }
    }

    /// The find bar: a query field, case toggle, live match count, and close.
    fn render_find_bar(&mut self, ui: &mut egui::Ui) {
        let Some(mut find) = self.find.take() else { return };
        let count = self.count_matches(&find);
        let mut close = false;
        egui::Panel::top("find-bar").show(ui, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label("🔍 Find:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut find.query)
                        .desired_width(240.0)
                        .hint_text("text in the visible terminals"),
                );
                if find.just_opened {
                    resp.request_focus();
                    find.just_opened = false;
                }
                ui.checkbox(&mut find.case_sensitive, "Case sensitive");
                let label = if find.query.is_empty() {
                    String::new()
                } else {
                    format!("{count} match(es)")
                };
                ui.label(RichText::new(label).weak());
                if ui.button("✕").on_hover_text("Close (Esc)").clicked() {
                    close = true;
                }
            });
            ui.add_space(3.0);
        });
        if close || ui.input(|i| i.key_pressed(Key::Escape)) {
            self.find = None;
        } else {
            self.find = Some(find);
        }
    }

    /// Total occurrences of the find query across the active tab's visible panes.
    fn count_matches(&self, find: &FindState) -> usize {
        if find.query.is_empty() {
            return 0;
        }
        let Some(TabContent::Terminal(panes)) = self.tabs.get(self.active).map(|t| &t.content)
        else {
            return 0;
        };
        let needle =
            if find.case_sensitive { find.query.clone() } else { find.query.to_lowercase() };
        panes
            .ids()
            .iter()
            .filter_map(|id| panes.get(*id))
            .map(|t| {
                let hay = if find.case_sensitive {
                    t.screen_text()
                } else {
                    t.screen_text().to_lowercase()
                };
                count_occurrences(&hay, &needle)
            })
            .sum()
    }

    /// Shows the placeholder for a tab whose session is displayed in a split pane
    /// on another tab, with a button to bring it back here.
    fn render_detached_tab(&mut self, ui: &mut egui::Ui, host_tab: u64) {
        let host_label = self
            .tabs
            .iter()
            .find(|t| t.id == host_tab)
            .map(|t| t.label.clone())
            .unwrap_or_else(|| "another tab".to_owned());
        let active = self.active;
        let mut bring_back = false;
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 3.0);
            ui.label(RichText::new("⇄ This session is shown in a split pane").heading());
            ui.add_space(6.0);
            ui.label(RichText::new(format!("on tab “{host_label}”.")).weak());
            ui.add_space(12.0);
            if ui.button("Bring back here").clicked() {
                bring_back = true;
            }
        });
        if bring_back {
            self.bring_back(active);
        }
    }

    /// Returns a detached tab's session from its host split pane back to this tab.
    fn bring_back(&mut self, detached_index: usize) {
        let my_id = self.tabs[detached_index].id;
        let TabContent::Detached { host_tab } = self.tabs[detached_index].content else { return };
        let Some(host_idx) = self.tabs.iter().position(|t| t.id == host_tab) else { return };
        let term = if let TabContent::Terminal(panes) = &mut self.tabs[host_idx].content {
            panes.moved_from(my_id).and_then(|tid| panes.remove_leaf(tid)).map(|(t, _)| t)
        } else {
            None
        };
        if let Some(term) = term {
            self.tabs[detached_index].origin_term = Some(term.id());
            self.tabs[detached_index].content = TabContent::Terminal(Box::new(Panes::new(term)));
            self.tabs[detached_index].connected_at.get_or_insert_with(std::time::Instant::now);
            self.active = detached_index;
        }
    }

    /// Shows the "session ended" banner for a terminal tab whose session closed,
    /// with its frozen output below and Restart / Save / Close actions.
    fn render_ended_tab(&mut self, ui: &mut egui::Ui) {
        enum EndAct {
            Restart,
            Save,
            Print,
            Close,
        }
        let active = self.active;
        let label = self.tabs.get(active).map(|t| t.label.clone()).unwrap_or_default();
        let can_restart = self.tabs.get(active).and_then(|t| t.restart.as_ref()).is_some();
        let mut act = None;
        egui::Panel::top("ended-banner").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("● {label} — session ended"))
                        .color(ui.visuals().warn_fg_color),
                );
                if ui
                    .add_enabled(can_restart, egui::Button::new("Restart"))
                    .on_hover_text("Reconnect / reopen this session")
                    .clicked()
                {
                    act = Some(EndAct::Restart);
                }
                if ui.button("Save output…").clicked() {
                    act = Some(EndAct::Save);
                }
                if ui.button("Print output").on_hover_text("Send the output to a printer").clicked()
                {
                    act = Some(EndAct::Print);
                }
                if ui.button("Close").clicked() {
                    act = Some(EndAct::Close);
                }
            });
            ui.add_space(4.0);
        });
        // The frozen terminal, read-only.
        if let Some(tab) = self.tabs.get_mut(active)
            && let TabContent::Terminal(panes) = &mut tab.content
        {
            let fs = tab.font_size;
            panes.show(ui, false, false, None, &[], None, fs, &[], &mut None);
        }
        match act {
            Some(EndAct::Restart) => {
                let ctx = ui.ctx().clone();
                self.restart_tab(active, &ctx);
            }
            Some(EndAct::Save) => self.save_tab_output(active),
            Some(EndAct::Print) => self.print_tab_output(active),
            Some(EndAct::Close) => self.close_tab(active),
            None => {}
        }
    }

    /// Restarts an ended tab's session in place, from its recorded origin.
    fn restart_tab(&mut self, index: usize, ctx: &egui::Context) {
        enum What {
            Shell,
            Ssh(Box<ConnectParams>),
            Serial(Box<SerialConfig>),
        }
        let what = match self.tabs.get(index).and_then(|t| t.restart.as_ref()) {
            Some(RestartKind::Shell) => What::Shell,
            Some(RestartKind::Ssh(p)) => What::Ssh(p.clone()),
            Some(RestartKind::Serial(c)) => What::Serial(c.clone()),
            None => return,
        };
        let size = TermSize::default();
        match what {
            What::Shell => {
                let repaint = ctx.clone();
                match LocalPty::spawn(size, move || repaint.request_repaint()) {
                    Ok((pty, output)) => {
                        let term = Terminal::new(Box::new(pty), output, size);
                        self.tabs[index].origin_term = Some(term.id());
                        self.tabs[index].content =
                            TabContent::Terminal(Box::new(Panes::new(Box::new(term))));
                        self.tabs[index].connected_at = Some(std::time::Instant::now());
                    }
                    Err(e) => self.error = Some(format!("Could not start a shell: {e:#}")),
                }
            }
            What::Serial(config) => {
                let repaint = ctx.clone();
                match SerialBackend::open(&config, move || repaint.request_repaint()) {
                    Ok((backend, output)) => {
                        let term = Terminal::new(Box::new(backend), output, size);
                        self.tabs[index].origin_term = Some(term.id());
                        self.tabs[index].content =
                            TabContent::Terminal(Box::new(Panes::new(Box::new(term))));
                        self.tabs[index].connected_at = Some(std::time::Instant::now());
                    }
                    Err(e) => self.error = Some(format!("Could not reopen the serial port: {e:#}")),
                }
            }
            What::Ssh(params) => {
                // Turn the tab back into a connecting tab; poll_connections will
                // re-establish the terminal (and re-arm restart) on success.
                let title = self.tabs[index].label.clone();
                let pending = PendingConnect::spawn((*params).clone(), ctx);
                let tab = &mut self.tabs[index];
                tab.content = TabContent::Connecting(Box::new(Connecting {
                    params: *params,
                    title,
                    pending: Some(pending),
                    log: Vec::new(),
                    status: "Reconnecting…".into(),
                    error: None,
                }));
                tab.files = None;
            }
        }
    }

    /// Saves the tab's original session's scrollback + screen to a chosen file.
    fn save_tab_output(&mut self, index: usize) {
        let text = match self.tabs.get(index) {
            Some(tab) => match &tab.content {
                TabContent::Terminal(panes) => {
                    let id = tab.origin_term.unwrap_or_else(|| panes.focused_id());
                    panes.get(id).or_else(|| panes.get(panes.focused_id())).map(|t| t.full_text())
                }
                _ => None,
            },
            None => None,
        };
        let Some(text) = text else { return };
        if let Some(path) =
            rfd::FileDialog::new().set_file_name("terminal-output.txt").save_file()
            && let Err(e) = std::fs::write(&path, text)
        {
            self.error = Some(format!("Could not save output: {e}"));
        }
    }

    /// The tab's original session's full text (scrollback + screen), if available.
    fn tab_output_text(&self, index: usize) -> Option<String> {
        let tab = self.tabs.get(index)?;
        match &tab.content {
            TabContent::Terminal(panes) => {
                let id = tab.origin_term.unwrap_or_else(|| panes.focused_id());
                panes.get(id).or_else(|| panes.get(panes.focused_id())).map(|t| t.full_text())
            }
            _ => None,
        }
    }

    /// Sends the tab's output to a printer via the platform print command.
    fn print_tab_output(&mut self, index: usize) {
        let Some(text) = self.tab_output_text(index) else { return };
        if let Err(e) = print_text(&text) {
            self.error = Some(format!("Could not print output: {e}"));
        }
    }

    fn start_port_scan(&mut self) {
        let n = &mut self.network;
        n.port_open.clear();
        n.port_error = None;
        let Some(ip) = network::resolve(n.port_target.trim()) else {
            n.port_error = Some("Enter a valid IP address or hostname.".into());
            return;
        };
        let ports: Vec<u16> = match n.port_mode {
            PortMode::Common => network::COMMON_PORTS.iter().map(|(p, _)| *p).collect(),
            PortMode::Custom => network::parse_ports(&n.port_spec),
        };
        if ports.is_empty() {
            n.port_error = Some("No ports to scan — check the list/range.".into());
            return;
        }
        n.port_scan = Some(network::scan_ports(ip, ports, std::time::Duration::from_millis(400)));
    }

    fn start_subnet_scan(&mut self) {
        let n = &mut self.network;
        n.subnet_hosts.clear();
        n.subnet_error = None;
        let Some(hosts) = network::parse_cidr(n.subnet_cidr.trim()) else {
            n.subnet_error = Some("Enter a CIDR like 10.0.0.0/24 (≤ /16).".into());
            return;
        };
        n.subnet_scan = Some(network::scan_subnet(hosts, std::time::Duration::from_millis(300)));
    }

    fn start_ping(&mut self) {
        let host = self.network.port_target.trim().to_owned();
        if host.is_empty() {
            self.network.ping_status = Some("Enter a host to ping.".into());
            return;
        }
        self.network.ping_status = Some(format!("Pinging {host}…"));
        self.network.ping = Some(network::ping_host(host));
    }

    /// Opens the Network toolbox and runs `tool` against a session's `host`.
    fn session_network_tool(&mut self, host: &str, tool: NetTool) {
        self.open_network_tab();
        let host = host.trim().to_owned();
        match tool {
            NetTool::Ping => {
                self.network.port_target = host;
                self.start_ping();
            }
            NetTool::PortScanCommon => {
                self.network.port_target = host;
                self.network.port_mode = PortMode::Common;
                self.start_port_scan();
            }
            NetTool::PortScanWellKnown => {
                self.network.port_target = host;
                self.network.port_mode = PortMode::Custom;
                self.network.port_spec = "1-1024".into();
                self.start_port_scan();
            }
            NetTool::SubnetScan => match network::resolve(&host) {
                Some(std::net::IpAddr::V4(ip)) => {
                    let o = ip.octets();
                    self.network.subnet_cidr = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
                    self.start_subnet_scan();
                }
                _ => {
                    self.network.subnet_error =
                        Some(format!("Could not resolve {host} to an IPv4 address."));
                }
            },
        }
    }

    /// The network toolbox: port scan, subnet scan, local ports, Wake-on-LAN.
    fn render_network(&mut self, ui: &mut egui::Ui) {
        // Drain streaming scan results (take the handle out to avoid a borrow clash).
        if let Some(h) = self.network.port_scan.take() {
            for hit in h.drain() {
                self.network.port_open.push((hit.port, hit.service));
            }
            if h.running() {
                self.network.port_scan = Some(h);
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(150));
            } else {
                self.network.port_open.sort_unstable();
                self.network.port_open.dedup();
            }
        }
        if let Some(h) = self.network.ping.take() {
            for msg in h.drain() {
                self.network.ping_status = Some(msg);
            }
            if h.running() {
                self.network.ping = Some(h);
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(150));
            }
        }
        if let Some(h) = self.network.subnet_scan.take() {
            for hit in h.drain() {
                self.network.subnet_hosts.push(hit);
            }
            if h.running() {
                self.network.subnet_scan = Some(h);
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(200));
            } else {
                self.network.subnet_hosts.sort_by_key(|h| u32::from(h.ip));
            }
        }

        let mut start_port = false;
        let mut start_ping = false;
        let mut start_subnet = false;
        let mut scan_host: Option<String> = None;
        let mut refresh_local = false;
        let mut send_wol = false;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(6.0);
            ui.heading("Network toolbox");
            ui.separator();

            // --- Port scanner ---
            ui.strong("Port scan");
            ui.horizontal(|ui| {
                ui.label("Host:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.network.port_target)
                        .hint_text("IP or hostname")
                        .desired_width(180.0),
                );
                ui.radio_value(&mut self.network.port_mode, PortMode::Common, "Common");
                ui.radio_value(&mut self.network.port_mode, PortMode::Custom, "Ports:");
                ui.add_enabled(
                    self.network.port_mode == PortMode::Custom,
                    egui::TextEdit::singleline(&mut self.network.port_spec)
                        .hint_text("22,80,443 or 1-1024")
                        .desired_width(140.0),
                );
            });
            ui.horizontal(|ui| {
                let scanning = self.network.port_scan.is_some();
                if ui.add_enabled(!scanning, egui::Button::new("Scan")).clicked() {
                    start_port = true;
                }
                if scanning {
                    ui.spinner();
                    if ui.button("Stop").clicked()
                        && let Some(h) = &self.network.port_scan
                    {
                        h.cancel();
                    }
                }
                let pinging = self.network.ping.is_some();
                if ui.add_enabled(!pinging, egui::Button::new("Ping")).clicked() {
                    start_ping = true;
                }
                if pinging {
                    ui.spinner();
                }
                if let Some(e) = &self.network.port_error {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
            });
            if let Some(s) = &self.network.ping_status {
                ui.label(RichText::new(s).weak());
            }
            if !self.network.port_open.is_empty() {
                let list = self
                    .network
                    .port_open
                    .iter()
                    .map(|(p, s)| if s.is_empty() { p.to_string() } else { format!("{p} ({s})") })
                    .collect::<Vec<_>>()
                    .join(", ");
                ui.label(format!("Open: {list}"));
            } else if self.network.port_scan.is_none() && !self.network.port_target.is_empty() {
                ui.label(RichText::new("No open ports found (or not scanned yet).").weak());
            }

            ui.add_space(10.0);
            ui.separator();

            // --- Subnet scanner ---
            ui.strong("Subnet scan");
            ui.horizontal(|ui| {
                ui.label("Subnet:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.network.subnet_cidr)
                        .hint_text("10.0.0.0/24")
                        .desired_width(180.0),
                );
                let scanning = self.network.subnet_scan.is_some();
                if ui.add_enabled(!scanning, egui::Button::new("Ping sweep")).clicked() {
                    start_subnet = true;
                }
                if scanning {
                    ui.spinner();
                    if ui.button("Stop").clicked()
                        && let Some(h) = &self.network.subnet_scan
                    {
                        h.cancel();
                    }
                }
            });
            if let Some(e) = &self.network.subnet_error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            for host in &self.network.subnet_hosts {
                ui.horizontal(|ui| {
                    let dot = if host.pingable { "🟢" } else { "⚪" };
                    ui.label(format!("{dot} {}", host.ip));
                    let svc = host
                        .services
                        .iter()
                        .map(|(_, s)| *s)
                        .collect::<Vec<_>>()
                        .join(", ");
                    if !svc.is_empty() {
                        ui.label(RichText::new(svc).weak());
                    }
                    if ui.small_button("Port scan").clicked() {
                        scan_host = Some(host.ip.to_string());
                    }
                });
            }

            ui.add_space(10.0);
            ui.separator();

            // --- Local listening ports ---
            ui.horizontal(|ui| {
                ui.strong("Local listening ports");
                if ui.button("Refresh").clicked() {
                    refresh_local = true;
                }
            });
            match &self.network.local_ports {
                None => {
                    ui.label(RichText::new("Click Refresh to list this host's open ports.").weak());
                }
                Some(ports) if ports.is_empty() => {
                    ui.label(RichText::new("No listening ports found.").weak());
                }
                Some(ports) => {
                    egui::Grid::new("local-ports").num_columns(3).striped(true).show(ui, |ui| {
                        ui.label(RichText::new("Proto").strong());
                        ui.label(RichText::new("Address").strong());
                        ui.label(RichText::new("Process").strong());
                        ui.end_row();
                        for p in ports {
                            ui.label(&p.proto);
                            ui.label(&p.address);
                            ui.label(&p.process);
                            ui.end_row();
                        }
                    });
                }
            }

            ui.add_space(10.0);
            ui.separator();

            // --- Wake-on-LAN ---
            ui.strong("Wake-on-LAN");
            ui.horizontal(|ui| {
                ui.label("MAC:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.network.wol_mac)
                        .hint_text("AA:BB:CC:DD:EE:FF")
                        .desired_width(180.0),
                );
                if ui.button("Send magic packet").clicked() {
                    send_wol = true;
                }
            });
            if let Some(s) = &self.network.wol_status {
                ui.label(RichText::new(s).weak());
            }
        });

        if start_port {
            self.start_port_scan();
        }
        if start_ping {
            self.start_ping();
        }
        if start_subnet {
            self.start_subnet_scan();
        }
        if let Some(ip) = scan_host {
            self.network.port_target = ip;
            self.network.port_mode = PortMode::Common;
            self.start_port_scan();
        }
        if refresh_local {
            match network::local_listening_ports() {
                Ok(ports) => self.network.local_ports = Some(ports),
                Err(e) => self.error = Some(e),
            }
        }
        if send_wol {
            self.network.wol_status = Some(match network::parse_mac(&self.network.wol_mac) {
                Some(mac) => match network::send_wol(mac) {
                    Ok(()) => "Magic packet sent.".into(),
                    Err(e) => format!("Failed: {e}"),
                },
                None => "Enter a valid MAC address.".into(),
            });
        }
    }

    fn render_servers(&mut self, ui: &mut egui::Ui) {
        enum Act {
            Start(String),
            Stop(String),
            Edit(String),
            Remove(String),
        }
        let mut act: Option<Act> = None;

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Quick servers");
            if ui.button("➕ Add server…").clicked() {
                self.dialog = Dialog::EditServer(ServerForm::new());
            }
        });
        ui.label(
            RichText::new("Serve a folder over HTTP/TFTP/SFTP, or run an iperf3 server.").weak(),
        );
        if let Some(task) = &self.admin_task {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("Running: {}…", task.label));
            });
        }
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if self.servers.is_empty() {
                ui.label(RichText::new("No servers configured. Add one to get started.").weak());
            }
            for entry in &self.servers {
                let id = entry.config.id.clone();
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&entry.config.name);
                        ui.label(RichText::new(entry.config.kind.label()).weak());
                        match &entry.running {
                            Some(r) => {
                                let timer = entry
                                    .stop_at
                                    .map(|t| {
                                        let secs = t.saturating_duration_since(std::time::Instant::now()).as_secs();
                                        format!("  ⏱ stops in {}m", secs / 60 + 1)
                                    })
                                    .unwrap_or_default();
                                ui.colored_label(Color32::GREEN, format!("● {}{timer}", r.addr()))
                            }
                            None => ui.label(
                                RichText::new(format!("○ {}:{}", entry.config.bind, entry.config.port))
                                    .weak(),
                            ),
                        };
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() {
                                act = Some(Act::Remove(id.clone()));
                            }
                            ui.add_enabled_ui(!entry.is_running(), |ui| {
                                if ui.small_button("Edit").clicked() {
                                    act = Some(Act::Edit(id.clone()));
                                }
                            });
                            if entry.is_running() {
                                if ui.button("Stop").clicked() {
                                    act = Some(Act::Stop(id.clone()));
                                }
                            } else if ui.button("Start").clicked() {
                                act = Some(Act::Start(id.clone()));
                            }
                        });
                    });
                    if !entry.log.is_empty() {
                        egui::ScrollArea::vertical()
                            .id_salt(("server-log", &id))
                            .max_height(140.0)
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for line in entry.log.iter().rev().take(200).rev() {
                                    ui.label(RichText::new(line).monospace().size(11.0));
                                }
                            });
                    }
                });
                ui.add_space(4.0);
            }
        });

        match act {
            Some(Act::Start(id)) => {
                self.dialog = Dialog::StartServer { id, auto_stop: true, minutes: "60".into() };
            }
            Some(Act::Stop(id)) => self.stop_server(&id),
            Some(Act::Edit(id)) => {
                if let Some(entry) = self.servers.iter().find(|e| e.config.id == id) {
                    self.dialog = Dialog::EditServer(ServerForm::from_config(&entry.config));
                }
            }
            Some(Act::Remove(id)) => {
                self.stop_server(&id);
                self.servers.retain(|e| e.config.id != id);
                if let Err(e) = self.servers_store.remove(&id) {
                    self.error = Some(format!("{e:#}"));
                }
            }
            None => {}
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
            Dialog::CreateCredential(_) => self.show_create_credential(ctx),
            Dialog::NewFolder { .. } => self.show_new_folder(ctx),
            Dialog::RenameFolder { .. } => self.show_rename_folder(ctx),
            Dialog::FolderAppearance { .. } => self.show_folder_appearance(ctx),
            Dialog::ConfirmDeleteVault => self.show_confirm_delete_vault(ctx),
            Dialog::ConfirmQuit => self.show_confirm_quit(ctx),
            Dialog::ConfirmImportVault { .. } => self.show_confirm_import_vault(ctx),
            Dialog::AskUsername(_) => self.show_ask_username(ctx),
            Dialog::AddSource(_) => self.show_add_source(ctx),
            Dialog::EditServer(_) => self.show_edit_server(ctx),
            Dialog::SerialConnect(_) => self.show_serial_connect(ctx),
            Dialog::StartServer { .. } => self.show_start_server(ctx),
            Dialog::ServerFix { .. } => self.show_server_fix(ctx),
            Dialog::MissingShare { .. } => self.show_missing_share(ctx),
            Dialog::DropMenu { .. } => self.show_drop_menu(ctx),
            Dialog::Keybindings { .. } => self.show_keybindings(ctx),
            Dialog::MacroEdit(_) => self.show_macro_edit(ctx),
            Dialog::ConfirmMacro { .. } => self.show_confirm_macro(ctx),
            Dialog::About => self.show_about(ctx),
            Dialog::ConnectCreds(_) => self.show_connect_creds(ctx),
        }
    }

    /// The connect-time username/password prompt (blank-password sessions and
    /// "Connect as…"), with an optional save-to-vault.
    fn show_connect_creds(&mut self, ctx: &egui::Context) {
        let mut connect = false;
        let mut cancel = false;
        if let Dialog::ConnectCreds(form) = &mut self.dialog {
            let title = form.title.clone();
            egui::Modal::new(egui::Id::new("connect-creds")).show(ctx, |ui| {
                ui.set_width(360.0);
                ui.heading("Connect");
                ui.label(RichText::new(title).weak());
                ui.add_space(6.0);
                egui::Grid::new("connect-creds-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Username");
                    ui.text_edit_singleline(&mut form.username);
                    ui.end_row();
                    ui.label("Password");
                    let pw = ui.add(egui::TextEdit::singleline(&mut form.password).password(true));
                    if pw.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                        connect = true;
                    }
                    ui.end_row();
                });
                ui.checkbox(&mut form.save, "Save to vault");
                if form.save {
                    ui.horizontal(|ui| {
                        ui.label("Save as:");
                        ui.text_edit_singleline(&mut form.save_name);
                    });
                }
                if let Some(err) = &form.error {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    connect |= ui.button("Connect").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if connect
            && let Dialog::ConnectCreds(form) = &mut self.dialog
        {
            // A save requires a name.
            if form.save && form.save_name.trim().is_empty() {
                form.error = Some("Enter a name for the vault entry, or uncheck \"Save to vault\".".into());
            } else {
                let form = form.clone();
                self.dialog = Dialog::None;
                self.connect_with_creds(*form, ctx);
            }
        } else if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Connects using credentials from the prompt, optionally saving them.
    fn connect_with_creds(&mut self, form: ConnectCredsForm, ctx: &egui::Context) {
        let username = form.username.trim().to_owned();
        let mut session = form.session;
        if !username.is_empty() {
            session.username = username.clone();
        }
        // Optionally store the credential in the vault (and rebind the session).
        if form.save && !form.save_name.trim().is_empty() {
            let name = form.save_name.trim().to_owned();
            let secret = Secret::Password {
                username: (!username.is_empty()).then(|| username.clone()),
                password: form.password.clone(),
            };
            if let Err(e) = self.store_secret(&name, secret) {
                self.error = Some(e);
                return;
            }
            if form.rebind {
                session.auth = Auth::Password { secret: name };
                let store = self
                    .find_session_anywhere(&session.id)
                    .map(|(s, _)| s)
                    .unwrap_or(StoreId::Local);
                let _ = self.store_upsert(&store, session.clone());
            }
        }
        let resolved = ResolvedAuth {
            material: AuthMaterial::Password(form.password),
            username: (!username.is_empty()).then_some(username),
        };
        self.connect_with(&session.name.clone(), &session, resolved, ctx);
    }

    /// Program info: version and links.
    fn show_about(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut close = false;
        egui::Window::new("About Wazowski")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.heading("Wazowski");
                ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                ui.label("A MobaXterm-style terminal & remote-session toolbox, in Rust.");
                ui.add_space(6.0);
                ui.hyperlink_to("GitHub repository", "https://github.com/HoleInTheSeat/Wazowski");
                ui.hyperlink_to(
                    "Releases & changelog",
                    "https://github.com/HoleInTheSeat/Wazowski/releases",
                );
                ui.add_space(6.0);
                ui.label(RichText::new("Licensed under GPL-3.0.").weak());
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    close = true;
                }
            });
        if close || !open {
            self.dialog = Dialog::None;
        }
    }

    /// The keybindings editor: lists every action, lets the user click one and
    /// press keys to rebind it, with reset-to-default and a save.
    fn show_keybindings(&mut self, ctx: &egui::Context) {
        let Dialog::Keybindings { capturing } = &mut self.dialog else { return };
        let mut capturing = *capturing;

        // If an action is awaiting a key, grab the first non-modifier key press.
        if let Some(action) = capturing {
            let captured = ctx.input_mut(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Key { key, pressed: true, modifiers, .. }
                        if !is_modifier_key(*key) =>
                    {
                        Some(KeyboardShortcut::new(*modifiers, *key))
                    }
                    _ => None,
                })
            });
            if let Some(shortcut) = captured {
                self.keymap.set(action, shortcut);
                capturing = None;
            }
        }

        let mut open = true;
        let mut close = false;
        let mut save = false;
        egui::Window::new("Keybindings")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Click a shortcut, then press the keys to rebind it.");
                ui.add_space(6.0);
                egui::Grid::new("keybinds-grid").num_columns(3).spacing([12.0, 6.0]).show(
                    ui,
                    |ui| {
                        for action in Action::ALL {
                            ui.label(action.label());
                            let label = if capturing == Some(action) {
                                "press keys…".to_owned()
                            } else {
                                self.keymap.text(action)
                            };
                            let selected = capturing == Some(action);
                            if ui.selectable_label(selected, label).clicked() {
                                capturing = if selected { None } else { Some(action) };
                            }
                            if ui.small_button("Reset").clicked() {
                                self.keymap.reset(action);
                                capturing = None;
                            }
                            ui.end_row();
                        }
                    },
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Close").clicked() {
                        close = true;
                    }
                    if capturing.is_some() {
                        ui.label(RichText::new("Esc to cancel capture").weak());
                    }
                });
            });

        if ctx.input(|i| i.key_pressed(Key::Escape)) && capturing.is_some() {
            capturing = None;
        }
        if save {
            if let Err(e) = self.keymap.save() {
                self.error = Some(format!("Could not save keybindings: {e:#}"));
            }
            close = true;
        }
        if close || !open {
            self.dialog = Dialog::None;
        } else if let Dialog::Keybindings { capturing: c } = &mut self.dialog {
            *c = capturing;
        }
    }

    // --- Macros -------------------------------------------------------------

    /// The macro editor: name plus an ordered, editable list of steps.
    fn show_macro_edit(&mut self, ctx: &egui::Context) {
        let Dialog::MacroEdit(form) = &mut self.dialog else { return };
        let mut save = false;
        let mut cancel = false;
        let mut open = true;
        egui::Window::new(if form.index.is_some() { "Edit macro" } else { "New macro" })
            .collapsible(false)
            .resizable(true)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut form.name);
                });
                ui.separator();
                ui.label("Steps:");
                let mut remove = None;
                let mut move_up = None;
                let len = form.steps.len();
                egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    for (i, step) in form.steps.iter_mut().enumerate() {
                        ui.push_id(i, |ui| {
                            ui.horizontal(|ui| {
                                step_editor(ui, step);
                                if ui.add_enabled(i > 0, egui::Button::new("↑").small()).clicked() {
                                    move_up = Some(i);
                                }
                                if ui.small_button("✕").clicked() {
                                    remove = Some(i);
                                }
                            });
                        });
                    }
                });
                let _ = len;
                if let Some(i) = move_up {
                    form.steps.swap(i - 1, i);
                }
                if let Some(i) = remove {
                    form.steps.remove(i);
                }
                ui.horizontal(|ui| {
                    if ui.button("+ Type text").clicked() {
                        form.steps.push(Step::Text { text: String::new(), enter: true });
                    }
                    if ui.button("+ Press key").clicked() {
                        form.steps.push(Step::Key { chord: "Enter".to_owned() });
                    }
                    if ui.button("+ Wait for…").clicked() {
                        form.steps.push(Step::Expect { text: String::new(), timeout_ms: 10_000 });
                    }
                    if ui.button("+ Delay").clicked() {
                        form.steps.push(Step::Delay { ms: 500 });
                    }
                });
                if let Some(err) = &form.error {
                    ui.colored_label(ui.visuals().error_fg_color, err);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if save {
            let Dialog::MacroEdit(form) = &mut self.dialog else { return };
            if form.name.trim().is_empty() {
                form.error = Some("Give the macro a name.".to_owned());
                return;
            }
            let m = Macro { name: form.name.trim().to_owned(), steps: form.steps.clone() };
            match form.index {
                Some(i) if i < self.macros.macros.len() => self.macros.macros[i] = m,
                _ => self.macros.macros.push(m),
            }
            self.save_macros();
            self.dialog = Dialog::None;
        } else if cancel || !open {
            self.dialog = Dialog::None;
        }
    }

    /// Confirms a macro run, listing its steps and the target, before playing it.
    fn show_confirm_macro(&mut self, ctx: &egui::Context) {
        let Dialog::ConfirmMacro { index, target } = &self.dialog else { return };
        let (index, target) = (*index, *target);
        let Some(m) = self.macros.macros.get(index) else {
            self.dialog = Dialog::None;
            return;
        };
        let (target_ids, _) = self.macro_targets(target);
        let where_to = target.describe(target_ids.len());
        let name = m.name.clone();
        let summaries: Vec<String> = m.steps.iter().map(Step::summary).collect();

        let mut run = false;
        let mut cancel = false;
        let mut open = true;
        egui::Window::new("Run macro?")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("Run \"{name}\" on {where_to}:"));
                ui.add_space(4.0);
                egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                    if summaries.is_empty() {
                        ui.label(RichText::new("(this macro has no steps)").weak());
                    }
                    for (i, s) in summaries.iter().enumerate() {
                        ui.label(format!("{}. {s}", i + 1));
                    }
                });
                ui.add_space(6.0);
                if target_ids.is_empty() {
                    ui.colored_label(ui.visuals().warn_fg_color, "No matching terminal to send to.");
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !target_ids.is_empty() && !summaries.is_empty(),
                            egui::Button::new("Run"),
                        )
                        .clicked()
                    {
                        run = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if run {
            self.start_macro(index, target);
            self.dialog = Dialog::None;
        } else if cancel || !open {
            self.dialog = Dialog::None;
        }
    }

    fn save_macros(&mut self) {
        if let Err(e) = self.macros.save() {
            self.error = Some(format!("Could not save macros: {e:#}"));
        }
    }

    /// Resolves a target to the terminal ids to send to and the primary one to
    /// watch for `Expect` steps.
    fn macro_targets(&self, target: MacroTarget) -> (Vec<u64>, u64) {
        let active_panes = self
            .tabs
            .get(self.active)
            .and_then(|t| match &t.content {
                TabContent::Terminal(p) => Some(p),
                _ => None,
            });
        match target {
            MacroTarget::ActivePane => match active_panes {
                Some(p) => (vec![p.focused_id()], p.focused_id()),
                None => (Vec::new(), 0),
            },
            MacroTarget::TabPanes => match active_panes {
                Some(p) => (p.ids(), p.focused_id()),
                None => (Vec::new(), 0),
            },
            MacroTarget::AllTerminals => {
                let mut ids = Vec::new();
                for tab in &self.tabs {
                    if let TabContent::Terminal(p) = &tab.content {
                        ids.extend(p.ids());
                    }
                }
                let primary = active_panes.map(|p| p.focused_id()).or_else(|| ids.first().copied());
                (ids.clone(), primary.unwrap_or(0))
            }
        }
    }

    fn start_macro(&mut self, index: usize, target: MacroTarget) {
        let Some(m) = self.macros.macros.get(index) else { return };
        let (target_ids, primary) = self.macro_targets(target);
        if target_ids.is_empty() {
            return;
        }
        self.macro_run = Some(MacroRun {
            name: m.name.clone(),
            steps: m.steps.clone(),
            index: 0,
            target_ids,
            primary,
            phase: RunPhase::Send,
        });
    }

    /// Sends `bytes` to each target terminal. When broadcast is on, it also
    /// mirrors to every other non-excluded terminal, like typed input does.
    fn macro_send(&mut self, ids: &[u64], bytes: &[u8]) {
        let broadcast = self.broadcast;
        for tab in &mut self.tabs {
            if let TabContent::Terminal(panes) = &mut tab.content {
                panes.for_each(|t| {
                    if ids.contains(&t.id()) || (broadcast && !t.broadcast_excluded()) {
                        t.write(bytes);
                    }
                });
            }
        }
    }

    /// Whether the terminal `id`'s visible screen currently contains `needle`.
    fn terminal_shows(&self, id: u64, needle: &str) -> bool {
        self.tabs.iter().any(|tab| {
            matches!(&tab.content, TabContent::Terminal(p)
                if p.get(id).is_some_and(|t| t.screen_text().contains(needle)))
        })
    }

    /// Advances the running macro, sending ready steps and honouring waits.
    fn advance_macro(&mut self, ctx: &egui::Context) {
        let Some(mut run) = self.macro_run.take() else { return };
        let now = std::time::Instant::now();
        let mut pending = false;
        while run.index < run.steps.len() {
            match run.phase.clone() {
                RunPhase::Send => match run.steps[run.index].clone() {
                    Step::Text { text, enter } => {
                        let mut bytes = text.into_bytes();
                        if enter {
                            bytes.push(b'\r');
                        }
                        self.macro_send(&run.target_ids, &bytes);
                        run.index += 1;
                    }
                    Step::Key { chord } => {
                        if let Some(bytes) = chord_to_bytes(&chord) {
                            self.macro_send(&run.target_ids, &bytes);
                        }
                        run.index += 1;
                    }
                    Step::Delay { ms } => {
                        run.phase =
                            RunPhase::Waiting { until: now + std::time::Duration::from_millis(ms) };
                        pending = true;
                        break;
                    }
                    Step::Expect { text, timeout_ms } => {
                        run.phase = RunPhase::Expecting {
                            text,
                            deadline: now + std::time::Duration::from_millis(timeout_ms),
                        };
                    }
                },
                RunPhase::Waiting { until } => {
                    if now >= until {
                        run.index += 1;
                        run.phase = RunPhase::Send;
                    } else {
                        pending = true;
                        break;
                    }
                }
                RunPhase::Expecting { text, deadline } => {
                    if self.terminal_shows(run.primary, &text) || now >= deadline {
                        run.index += 1;
                        run.phase = RunPhase::Send;
                    } else {
                        pending = true;
                        break;
                    }
                }
            }
        }
        if run.index < run.steps.len() {
            self.macro_run = Some(run);
            if pending {
                ctx.request_repaint_after(std::time::Duration::from_millis(50));
            }
        }
    }

    /// Asks whether a drag-and-drop should move or copy, then performs it.
    fn show_drop_menu(&mut self, ctx: &egui::Context) {
        let Dialog::DropMenu { payload, to, folder } = &self.dialog else { return };
        let (to, folder) = (to.clone(), folder.clone());
        let dest_label = if folder.is_empty() { "root".to_owned() } else { folder.clone() };
        let (what, move_action, copy_action) = match payload {
            DragPayload::Session { store, id } => (
                "session".to_owned(),
                TreeAction::MoveTo { from: store.clone(), id: id.clone(), to: to.clone(), folder: folder.clone() },
                TreeAction::CopyTo { from: store.clone(), id: id.clone(), to: to.clone(), folder: folder.clone() },
            ),
            DragPayload::Folder { store, path } => (
                "folder".to_owned(),
                TreeAction::MoveFolder { from: store.clone(), folder: path.clone(), to: to.clone(), parent: folder.clone() },
                TreeAction::CopyFolder { from: store.clone(), folder: path.clone(), to: to.clone(), parent: folder.clone() },
            ),
        };
        let mut chosen: Option<TreeAction> = None;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("drop-menu")).show(ctx, |ui| {
            ui.set_width(300.0);
            ui.heading(format!("Drop {what}"));
            ui.label(RichText::new(format!("Into: {dest_label}")).weak());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Move here").clicked() {
                    chosen = Some(move_action.clone());
                }
                if ui.button("Copy here").clicked() {
                    chosen = Some(copy_action.clone());
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if let Some(act) = chosen {
            self.dialog = Dialog::None;
            self.apply_tree_action(Some(act), ctx);
        } else if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_edit_server(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        let mut browse = false;
        let bind_options = wazowski_servers::bind_options();
        if let Dialog::EditServer(f) = &mut self.dialog {
            let title = if f.id.is_some() { "Edit server" } else { "New server" };
            egui::Modal::new(egui::Id::new("edit-server")).show(ctx, |ui| {
                ui.set_width(440.0);
                ui.heading(title);
                ui.add_space(6.0);
                egui::Grid::new("server-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut f.name);
                    ui.end_row();
                    ui.label("Type");
                    egui::ComboBox::from_id_salt("server-kind")
                        .selected_text(f.kind.label())
                        .show_ui(ui, |ui| {
                            for kind in
                                [ServerKind::Http, ServerKind::Tftp, ServerKind::Sftp, ServerKind::Iperf]
                            {
                                if ui.selectable_value(&mut f.kind, kind, kind.label()).clicked() {
                                    // Suggest the type's default port when switching.
                                    f.port = kind.default_port().to_string();
                                }
                            }
                        });
                    ui.end_row();
                    if f.kind.uses_root() {
                        ui.label("Folder");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut f.root)
                                    .hint_text("folder to serve")
                                    .desired_width(240.0),
                            );
                            browse |= ui.button("Browse…").clicked();
                        });
                        ui.end_row();
                    }
                    ui.label("Bind");
                    egui::ComboBox::from_id_salt("server-bind")
                        .selected_text(
                            bind_options
                                .iter()
                                .find(|(_, ip)| *ip == f.bind)
                                .map(|(l, _)| l.clone())
                                .unwrap_or_else(|| f.bind.to_string()),
                        )
                        .show_ui(ui, |ui| {
                            for (label, ip) in &bind_options {
                                ui.selectable_value(&mut f.bind, *ip, label);
                            }
                        });
                    ui.end_row();
                    ui.label("Port");
                    ui.text_edit_singleline(&mut f.port);
                    ui.end_row();
                    if matches!(f.kind, ServerKind::Tftp | ServerKind::Sftp) {
                        ui.label("Allow uploads");
                        ui.checkbox(&mut f.writable, "writable");
                        ui.end_row();
                    }
                    if f.kind == ServerKind::Sftp {
                        ui.label("Username");
                        ui.add(egui::TextEdit::singleline(&mut f.username).hint_text("(any if blank)"));
                        ui.end_row();
                        ui.label("Password");
                        ui.add(
                            egui::TextEdit::singleline(&mut f.password)
                                .password(true)
                                .hint_text("(any if blank)"),
                        );
                        ui.end_row();
                    }
                });
                if f.kind == ServerKind::Iperf {
                    ui.label(RichText::new("Requires the iperf3 binary on your PATH.").weak());
                }
                if let Some(error) = &f.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    save |= ui.button("Save").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if browse
            && let Some(dir) = rfd::FileDialog::new().pick_folder()
            && let Dialog::EditServer(f) = &mut self.dialog
        {
            f.root = dir.to_string_lossy().into_owned();
        }
        if save {
            self.try_save_server();
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn try_save_server(&mut self) {
        let Dialog::EditServer(f) = &self.dialog else { return };
        let port: u16 = match f.port.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => return self.set_server_error("Port must be a number from 1–65535."),
        };
        let name = if f.name.trim().is_empty() { f.kind.label().to_owned() } else { f.name.trim().to_owned() };
        if f.kind.uses_root() && f.root.trim().is_empty() {
            return self.set_server_error("Choose a folder to serve.");
        }
        let id = f.id.clone().unwrap_or_else(|| Session::new("", "", "").id);
        let config = ServerConfig {
            id: id.clone(),
            name,
            kind: f.kind,
            root: PathBuf::from(f.root.trim()),
            bind: f.bind,
            port,
            writable: f.writable,
            username: f.username.trim().to_owned(),
            password: f.password.clone(),
        };
        if let Err(e) = self.servers_store.upsert(config.clone()) {
            return self.set_server_error(&format!("{e:#}"));
        }
        match self.servers.iter_mut().find(|e| e.config.id == id) {
            Some(entry) => entry.config = config,
            None => self.servers.push(ServerEntry::new(config)),
        }
        self.dialog = Dialog::None;
    }

    fn set_server_error(&mut self, message: &str) {
        if let Dialog::EditServer(f) = &mut self.dialog {
            f.error = Some(message.to_owned());
        }
    }

    fn show_serial_connect(&mut self, ctx: &egui::Context) {
        let mut connect = false;
        let mut cancel = false;
        let mut refresh = false;
        if let Dialog::SerialConnect(f) = &mut self.dialog {
            egui::Modal::new(egui::Id::new("serial-connect")).show(ctx, |ui| {
                ui.set_width(380.0);
                ui.heading("New serial connection");
                ui.add_space(6.0);
                egui::Grid::new("serial-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Port");
                    if f.locked_port {
                        ui.label(RichText::new(&f.path).monospace());
                    } else {
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut f.filter)
                                    .hint_text("filter, e.g. usb")
                                    .desired_width(90.0),
                            )
                            .on_hover_text("Case-insensitive substring filter for the port list");
                            let needle = f.filter.to_lowercase();
                            let matches: Vec<String> = f
                                .ports
                                .iter()
                                .filter(|p| needle.is_empty() || p.to_lowercase().contains(&needle))
                                .cloned()
                                .collect();
                            egui::ComboBox::from_id_salt("serial-port")
                                .selected_text(if f.path.is_empty() { "(none)" } else { &f.path })
                                .show_ui(ui, |ui| {
                                    for port in &matches {
                                        ui.selectable_value(&mut f.path, port.clone(), port);
                                    }
                                });
                            refresh |= ui.button("⟳").on_hover_text("Rescan ports").clicked();
                        });
                    }
                    ui.end_row();
                    ui.label("Baud");
                    egui::ComboBox::from_id_salt("serial-baud")
                        .selected_text(&f.baud)
                        .show_ui(ui, |ui| {
                            for b in COMMON_BAUDS {
                                ui.selectable_value(&mut f.baud, b.to_string(), b.to_string());
                            }
                        });
                    ui.end_row();
                    ui.label("Data bits");
                    egui::ComboBox::from_id_salt("serial-data")
                        .selected_text(f.data_bits.to_string())
                        .show_ui(ui, |ui| {
                            for b in [8u8, 7, 6, 5] {
                                ui.selectable_value(&mut f.data_bits, b, b.to_string());
                            }
                        });
                    ui.end_row();
                    ui.label("Parity");
                    egui::ComboBox::from_id_salt("serial-parity")
                        .selected_text(format!("{:?}", f.parity))
                        .show_ui(ui, |ui| {
                            for p in [SerialParity::None, SerialParity::Odd, SerialParity::Even] {
                                ui.selectable_value(&mut f.parity, p, format!("{p:?}"));
                            }
                        });
                    ui.end_row();
                    ui.label("Stop bits");
                    egui::ComboBox::from_id_salt("serial-stop")
                        .selected_text(f.stop_bits.to_string())
                        .show_ui(ui, |ui| {
                            for b in [1u8, 2] {
                                ui.selectable_value(&mut f.stop_bits, b, b.to_string());
                            }
                        });
                    ui.end_row();
                    ui.label("Flow control");
                    egui::ComboBox::from_id_salt("serial-flow")
                        .selected_text(format!("{:?}", f.flow))
                        .show_ui(ui, |ui| {
                            for fc in [SerialFlow::None, SerialFlow::Software, SerialFlow::Hardware] {
                                ui.selectable_value(&mut f.flow, fc, format!("{fc:?}"));
                            }
                        });
                    ui.end_row();
                });
                if f.ports.is_empty() {
                    ui.colored_label(Color32::LIGHT_YELLOW, "No serial ports detected.");
                }
                if let Some(error) = &f.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    connect |= ui.button("Connect").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if refresh
            && let Dialog::SerialConnect(f) = &mut self.dialog
        {
            f.ports = available_ports();
            if !f.ports.contains(&f.path) {
                f.path = f.ports.first().cloned().unwrap_or_default();
            }
        }
        if connect {
            self.open_serial(ctx);
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn open_serial(&mut self, ctx: &egui::Context) {
        let Dialog::SerialConnect(f) = &self.dialog else { return };
        if f.path.is_empty() {
            return self.set_serial_error("Choose a serial port.");
        }
        let baud: u32 = match f.baud.trim().parse() {
            Ok(b) if b > 0 => b,
            _ => return self.set_serial_error("Baud must be a positive number."),
        };
        let config = SerialConfig {
            path: f.path.clone(),
            baud,
            data_bits: f.data_bits,
            parity: f.parity,
            stop_bits: f.stop_bits,
            flow: f.flow,
        };
        self.dialog = Dialog::None;
        if let Err(e) = self.open_serial_config(config, ctx) {
            self.set_serial_error(&format!("{e:#}"));
        }
    }

    /// Opens a serial connection tab from a config (shared by the dialog and
    /// tab duplication).
    fn open_serial_config(
        &mut self,
        config: SerialConfig,
        ctx: &egui::Context,
    ) -> anyhow::Result<()> {
        let label = format!("Serial {}", config.path.rsplit('/').next().unwrap_or(&config.path));
        let size = TermSize::default();
        let repaint = ctx.clone();
        let (backend, output) = SerialBackend::open(&config, move || repaint.request_repaint())?;
        let term = Terminal::new(Box::new(backend), output, size);
        let panes = Panes::new(Box::new(term));
        self.push_tab(label, TabContent::Terminal(Box::new(panes)), None);
        if let Some(tab) = self.tabs.get_mut(self.active) {
            tab.restart = Some(RestartKind::Serial(Box::new(config)));
        }
        Ok(())
    }

    fn set_serial_error(&mut self, message: &str) {
        if let Dialog::SerialConnect(f) = &mut self.dialog {
            f.error = Some(message.to_owned());
        }
    }

    fn show_start_server(&mut self, ctx: &egui::Context) {
        let mut start = false;
        let mut cancel = false;
        let name = if let Dialog::StartServer { id, .. } = &self.dialog {
            self.servers.iter().find(|e| e.config.id == *id).map(|e| e.config.name.clone())
        } else {
            None
        };
        if let Dialog::StartServer { auto_stop, minutes, .. } = &mut self.dialog {
            egui::Modal::new(egui::Id::new("start-server")).show(ctx, |ui| {
                ui.set_width(340.0);
                ui.heading(format!("Start {}", name.as_deref().unwrap_or("server")));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.checkbox(auto_stop, "Stop server after");
                    ui.add_enabled(*auto_stop, egui::TextEdit::singleline(minutes).desired_width(50.0));
                    ui.label("minutes");
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    start |= ui.button("Start").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if start
            && let Dialog::StartServer { id, auto_stop, minutes } = &self.dialog
        {
            let auto = if *auto_stop {
                match minutes.trim().parse::<u64>() {
                    Ok(m) if m > 0 => Some(m),
                    _ => {
                        // Keep the dialog open; a cheap nudge via the error bar.
                        self.error = Some("Enter a positive number of minutes.".into());
                        return;
                    }
                }
            } else {
                None
            };
            let id = id.clone();
            self.dialog = Dialog::None;
            let ctx = ctx.clone();
            self.start_server(&id, auto, &ctx);
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_server_fix(&mut self, ctx: &egui::Context) {
        let Dialog::ServerFix { title, message, command, retry_id, restart_required } = &self.dialog
        else {
            return;
        };
        let (title, message, command, retry_id, restart_required) = (
            title.clone(),
            message.clone(),
            command.clone(),
            retry_id.clone(),
            *restart_required,
        );
        let mut run = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("server-fix")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.heading(RichText::new(format!("⚠ {title}")).color(Color32::LIGHT_YELLOW));
            ui.label(message);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if command.is_some() {
                    let label = if wazowski_servers::needs_pkexec() {
                        "Run (asks for your password)"
                    } else {
                        "Run"
                    };
                    run |= ui.button(label).clicked();
                }
                cancel |= ui.button("Close").clicked();
            });
        });
        if run
            && let Some(cmd) = command
        {
            self.dialog = Dialog::None;
            let retry = (!retry_id.is_empty()).then_some(retry_id);
            self.run_admin(title, cmd, retry, restart_required);
        } else if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_missing_share(&mut self, ctx: &egui::Context) {
        let Dialog::MissingShare { id } = &self.dialog else { return };
        let id = id.clone();
        let Some(source) = self.shared.iter().find(|s| s.id() == id) else {
            self.dialog = Dialog::None;
            return;
        };
        let name = source.name().to_owned();
        let can_recreate = source.can_recreate();
        let status = source.status().unwrap_or("the shared source is unavailable").to_owned();
        let mut choice: Option<u8> = None;
        egui::Modal::new(egui::Id::new("missing-share")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.heading(RichText::new("⚠ Shared source unavailable").color(Color32::LIGHT_RED));
            ui.label(format!("'{name}': {status}"));
            ui.label(
                RichText::new("Your local cache is still available (read-only).").weak(),
            );
            ui.add_space(8.0);
            ui.vertical(|ui| {
                if can_recreate && ui.button("Create it now (from local cache)").clicked() {
                    choice = Some(0);
                }
                if ui.button("Keep using local cache").clicked() {
                    choice = Some(1);
                }
                if ui.button("Remove shared source").clicked() {
                    choice = Some(2);
                }
            });
        });
        match choice {
            Some(0) => {
                if let Some(source) = self.shared.iter_mut().find(|s| s.id() == id) {
                    match source.create() {
                        Ok(()) => source.reload(),
                        Err(e) => self.error = Some(format!("Could not create the file: {e:#}")),
                    }
                }
                self.dialog = Dialog::None;
            }
            Some(1) => self.dialog = Dialog::None,
            Some(2) => {
                if let Err(e) = self.remove_source(&id) {
                    self.error = Some(format!("{e:#}"));
                }
                self.dialog = Dialog::None;
            }
            _ => {}
        }
    }

    fn show_add_source(&mut self, ctx: &egui::Context) {
        let mut add = false;
        let mut cancel = false;
        let mut browse_folder = false;
        let mut browse_key = false;
        if let Dialog::AddSource(f) = &mut self.dialog {
            let editing = f.edit_id.is_some();
            egui::Modal::new(egui::Id::new("add-source")).show(ctx, |ui| {
                ui.set_width(460.0);
                ui.heading(if editing { "Edit shared source" } else { "Add shared source" });
                ui.label(
                    RichText::new(
                        "Shared sessions are cached locally (available offline) and never \
                         store secrets — credentials are created locally on first use.",
                    )
                    .weak(),
                );
                ui.add_space(6.0);
                egui::Grid::new("add-source-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut f.name);
                    ui.end_row();
                    ui.label("Type");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut f.kind, SourceKind::Folder, "Folder / file");
                        ui.selectable_value(&mut f.kind, SourceKind::Git, "Git repo");
                    });
                    ui.end_row();

                    match f.kind {
                        SourceKind::Folder => {
                            ui.label("Shared file");
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut f.path)
                                        .hint_text("/path/to/team-sessions.toml")
                                        .desired_width(240.0),
                                );
                                browse_folder |= ui.button("Browse…").clicked();
                            });
                            ui.end_row();
                        }
                        SourceKind::Git => {
                            ui.label("Repository URL");
                            ui.add(
                                egui::TextEdit::singleline(&mut f.url)
                                    .hint_text("https://… or git@…:group/repo.git"),
                            );
                            ui.end_row();
                            ui.label("Branch");
                            ui.add(egui::TextEdit::singleline(&mut f.branch).hint_text("(default)"));
                            ui.end_row();
                            ui.label("File in repo");
                            ui.text_edit_singleline(&mut f.file);
                            ui.end_row();
                            ui.label("Auth");
                            egui::ComboBox::from_id_salt("git-auth")
                                .selected_text(match f.auth {
                                    GitAuthKind::None => "None / ambient",
                                    GitAuthKind::Https => "HTTPS token",
                                    GitAuthKind::Ssh => "SSH key",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut f.auth, GitAuthKind::None, "None / ambient");
                                    ui.selectable_value(&mut f.auth, GitAuthKind::Https, "HTTPS token");
                                    ui.selectable_value(&mut f.auth, GitAuthKind::Ssh, "SSH key");
                                });
                            ui.end_row();
                            match f.auth {
                                GitAuthKind::Https => {
                                    ui.label("Username");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut f.username)
                                            .hint_text("(optional for GitHub PATs)"),
                                    );
                                    ui.end_row();
                                    ui.label("Token");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut f.token)
                                            .password(true)
                                            .hint_text("stored in your OS keyring"),
                                    );
                                    ui.end_row();
                                }
                                GitAuthKind::Ssh => {
                                    ui.label("Private key");
                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::TextEdit::singleline(&mut f.key_path)
                                                .hint_text("(optional; uses agent if blank)")
                                                .desired_width(240.0),
                                        );
                                        browse_key |= ui.button("Browse…").clicked();
                                    });
                                    ui.end_row();
                                }
                                GitAuthKind::None => {}
                            }
                        }
                    }
                });
                ui.add_space(6.0);
                appearance_picker(ui, &mut f.icon, &mut f.color, "🌐");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    add |= ui.button(if editing { "Save" } else { "Add" }).clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if browse_folder
            && let Some(picked) = rfd::FileDialog::new()
                .set_file_name("team-sessions.toml")
                .save_file()
            && let Dialog::AddSource(f) = &mut self.dialog
        {
            f.path = picked.to_string_lossy().into_owned();
        }
        if browse_key
            && let Some(picked) = rfd::FileDialog::new().pick_file()
            && let Dialog::AddSource(f) = &mut self.dialog
        {
            f.key_path = picked.to_string_lossy().into_owned();
        }
        if add
            && let Dialog::AddSource(f) = &self.dialog
        {
            let editing = f.edit_id.is_some();
            match self.build_source_def(f) {
                Ok((def, token)) => {
                    if editing {
                        self.update_source(def, token);
                    } else {
                        self.add_source(def, token);
                    }
                    self.dialog = Dialog::None;
                }
                Err(e) => self.error = Some(e),
            }
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Validates the add-source form into a [`SourceDef`] (and an HTTPS token to stash).
    fn build_source_def(&self, f: &AddSourceForm) -> Result<(SourceDef, Option<String>), String> {
        let name = f.name.trim().to_owned();
        if name.is_empty() {
            return Err("Give the source a name.".into());
        }
        let id = f.edit_id.clone().unwrap_or_else(|| Session::new("", "", "").id);
        let mut def = SourceDef {
            id,
            name,
            kind: f.kind,
            path: PathBuf::new(),
            url: String::new(),
            branch: f.branch.trim().to_owned(),
            file: if f.file.trim().is_empty() {
                "wazowski-sessions.toml".into()
            } else {
                f.file.trim().to_owned()
            },
            auth: f.auth,
            username: f.username.trim().to_owned(),
            key_path: f.key_path.trim().to_owned(),
            icon: f.icon.clone(),
            color: f.color,
        };
        let mut token = None;
        match f.kind {
            SourceKind::Folder => {
                if f.path.trim().is_empty() {
                    return Err("Choose a shared file path.".into());
                }
                def.path = PathBuf::from(f.path.trim());
            }
            SourceKind::Git => {
                if f.url.trim().is_empty() {
                    return Err("Enter the repository URL.".into());
                }
                def.url = f.url.trim().to_owned();
                if f.auth == GitAuthKind::Https {
                    if f.token.is_empty() {
                        return Err("Enter the HTTPS token (or choose a different auth).".into());
                    }
                    token = Some(f.token.clone());
                }
            }
        }
        Ok((def, token))
    }

    fn add_source(&mut self, def: SourceDef, token: Option<String>) {
        if let Some(token) = token
            && let Err(e) = sources::store_git_token(&def.id, &token)
        {
            self.error = Some(format!("Could not store the token: {e:#}"));
            return;
        }
        if let Err(e) = self.sources_config.add(def.clone()) {
            self.error = Some(format!("{e:#}"));
            return;
        }
        let cache = sources::cache_dir().unwrap_or_else(|_| "shared-cache".into());
        let mut source = SharedSource::open(def, &cache);
        // A new source's file usually doesn't exist yet; create it so the share
        // is immediately usable (and later deletion registers as offline).
        if !source.available()
            && source.missing()
            && let Err(e) = source.create()
        {
            self.error = Some(format!("Added, but could not create the shared file: {e:#}"));
        }
        self.shared.push(source);
    }

    /// Applies edits to an existing shared source: updates its token, config
    /// entry, and live state (re-opening from the new definition).
    fn update_source(&mut self, def: SourceDef, token: Option<String>) {
        if def.auth == GitAuthKind::Https {
            if let Some(token) = token
                && let Err(e) = sources::store_git_token(&def.id, &token)
            {
                self.error = Some(format!("Could not store the token: {e:#}"));
                return;
            }
        } else {
            sources::delete_git_token(&def.id);
        }
        if let Err(e) = self.sources_config.update(def.clone()) {
            self.error = Some(format!("{e:#}"));
            return;
        }
        let cache = sources::cache_dir().unwrap_or_else(|_| "shared-cache".into());
        let source = SharedSource::open(def.clone(), &cache);
        match self.shared.iter_mut().find(|s| s.id() == def.id) {
            Some(slot) => *slot = source,
            None => self.shared.push(source),
        }
    }

    fn show_confirm_quit(&mut self, ctx: &egui::Context) {
        let open = self.tabs.len();
        let mut quit = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("confirm-quit")).show(ctx, |ui| {
            ui.set_width(340.0);
            ui.heading("Quit Wazowski?");
            ui.label(format!(
                "{open} tab{} open. Closing the window will end {} session{}.",
                if open == 1 { " is" } else { "s are" },
                if open == 1 { "that" } else { "those" },
                if open == 1 { "" } else { "s" },
            ));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Quit").clicked() {
                    quit = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if quit {
            self.quitting = true;
            self.dialog = Dialog::None;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Picks a vault file to import; confirms if one already exists.
    fn import_vault(&mut self) {
        let Some(src) = rfd::FileDialog::new().pick_file() else { return };
        if Vault::exists(&self.vault_path) {
            self.dialog = Dialog::ConfirmImportVault { src };
        } else {
            self.copy_imported_vault(&src);
        }
    }

    fn show_confirm_import_vault(&mut self, ctx: &egui::Context) {
        let mut import = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("confirm-import")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.heading(RichText::new("⚠ Replace existing vault?").color(Color32::LIGHT_RED));
            ui.label(
                "Importing will overwrite your current vault file and its stored \
                 credentials. Back up first if unsure.",
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                import |= ui.button("Replace and import").clicked();
                cancel |= ui.button("Cancel").clicked();
            });
        });
        if import
            && let Dialog::ConfirmImportVault { src } = &self.dialog
        {
            let src = src.clone();
            self.copy_imported_vault(&src);
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Copies an external vault file into place and resets vault state.
    fn copy_imported_vault(&mut self, src: &std::path::Path) {
        if let Some(parent) = self.vault_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            self.error = Some(format!("Could not prepare the vault directory: {e}"));
            return;
        }
        if let Err(e) = std::fs::copy(src, &self.vault_path) {
            self.error = Some(format!("Import failed: {e}"));
            self.dialog = Dialog::None;
            return;
        }
        // The imported vault has its own password; clear any stale saved key.
        let _ = Vault::disable_keyring_unlock();
        self.vault = initial_vault_state(&self.vault_path);
        self.dialog = Dialog::None;
    }

    fn show_confirm_delete_vault(&mut self, ctx: &egui::Context) {
        let mut delete = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("delete-vault")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.heading(RichText::new("⚠ Delete vault").color(Color32::LIGHT_RED));
            ui.label(
                "This permanently deletes the encrypted vault file and all stored \
                 passwords and keys. Sessions that reference them will prompt for new \
                 credentials. Back up first if unsure.",
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("Delete vault").clicked() {
                    delete = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if delete {
            self.delete_vault();
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_ask_username(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::AskUsername(prompt) = &mut self.dialog {
            egui::Modal::new(egui::Id::new("ask-username")).show(ctx, |ui| {
                ui.set_width(320.0);
                ui.heading("Username");
                ui.label(
                    RichText::new(format!("Enter the username for {}.", prompt.session.host))
                        .weak(),
                );
                ui.add_space(6.0);
                let field = ui.add(
                    egui::TextEdit::singleline(&mut prompt.username).hint_text("Username"),
                );
                autofocus(ui, &field);
                submit |= entered(ui, &field);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    submit |= ui.button("Connect").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if submit
            && let Dialog::AskUsername(prompt) = &self.dialog
        {
            let username = prompt.username.trim().to_owned();
            if !username.is_empty() {
                let (title, mut session, material) =
                    (prompt.title.clone(), prompt.session.clone(), prompt.material.clone());
                session.username = username; // in-memory only; not persisted
                self.dialog = Dialog::None;
                let session_id = self.saved_session_id(&session);
                self.open_connecting_tab(
                    title,
                    self.params_for(&session, material),
                    session_id,
                    ctx,
                );
            }
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_new_folder(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::NewFolder { parent, name, .. } = &mut self.dialog {
            let heading =
                if parent.is_empty() { "New folder".to_owned() } else { format!("New folder in {parent}") };
            egui::Modal::new(egui::Id::new("new-folder")).show(ctx, |ui| {
                ui.set_width(300.0);
                ui.heading(heading);
                let field = ui.add(egui::TextEdit::singleline(name).hint_text("Folder name"));
                autofocus(ui, &field);
                submit |= entered(ui, &field);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    submit |= ui.button("Create").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if submit
            && let Dialog::NewFolder { target, parent, name } = &self.dialog
        {
            let name = name.trim().trim_matches('/');
            // Nest under the parent folder when creating a subfolder.
            let full = if parent.is_empty() { name.to_owned() } else { format!("{parent}/{name}") };
            let target = target.clone();
            if !name.is_empty()
                && let Err(e) = self.store_add_folder(&target, &full)
            {
                self.error = Some(format!("{e:#}"));
            }
            self.dialog = Dialog::None;
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    fn show_rename_folder(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::RenameFolder { name, .. } = &mut self.dialog {
            egui::Modal::new(egui::Id::new("rename-folder")).show(ctx, |ui| {
                ui.set_width(300.0);
                ui.heading("Rename folder");
                let field = ui.add(egui::TextEdit::singleline(name));
                autofocus(ui, &field);
                submit |= entered(ui, &field);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    submit |= ui.button("Rename").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if submit
            && let Dialog::RenameFolder { target, old, name } = &self.dialog
        {
            let (target, old, name) = (target.clone(), old.clone(), name.clone());
            if let Err(e) = self.store_rename_folder(&target, &old, &name) {
                self.error = Some(format!("{e:#}"));
            }
            self.dialog = Dialog::None;
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Dialog to set a folder's custom icon and color.
    fn show_folder_appearance(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        if let Dialog::FolderAppearance { folder, icon, color, .. } = &mut self.dialog {
            let folder = folder.clone();
            egui::Modal::new(egui::Id::new("folder-appearance")).show(ctx, |ui| {
                ui.set_width(340.0);
                ui.heading("Folder appearance");
                ui.label(RichText::new(folder).weak());
                ui.add_space(6.0);
                appearance_picker(ui, icon, color, "📁");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    save |= ui.button("Save").clicked();
                    cancel |= ui.button("Cancel").clicked();
                });
            });
        }
        if save
            && let Dialog::FolderAppearance { target, folder, icon, color } = &self.dialog
        {
            let (target, folder) = (target.clone(), folder.clone());
            let style = FolderStyle { icon: icon.clone(), color: *color };
            if let Err(e) = self.store_set_folder_style(&target, &folder, style) {
                self.error = Some(format!("{e:#}"));
            }
            self.dialog = Dialog::None;
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// First-use prompt to create a session's referenced-but-missing credential.
    fn show_create_credential(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        if let Dialog::CreateCredential(prompt) = &mut self.dialog {
            let form = &mut prompt.form;
            egui::Modal::new(egui::Id::new("create-credential")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.heading("Create credential");
                ui.label(
                    RichText::new(format!(
                        "This session needs a vault entry named '{}'. Create it now.",
                        form.name
                    ))
                    .weak(),
                );
                ui.add_space(6.0);
                egui::Grid::new("cred-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Type");
                    egui::ComboBox::from_id_salt("cred-kind")
                        .selected_text(match form.kind {
                            SecretKind::Password => "Password",
                            SecretKind::Key => "Private key",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut form.kind, SecretKind::Password, "Password");
                            ui.selectable_value(&mut form.kind, SecretKind::Key, "Private key");
                        });
                    ui.end_row();
                    ui.label("Username");
                    ui.add(
                        egui::TextEdit::singleline(&mut form.username)
                            .hint_text("(optional, overrides the session's)"),
                    );
                    ui.end_row();
                    match form.kind {
                        SecretKind::Password => {
                            ui.label("Password");
                            let resp = ui.add(egui::TextEdit::singleline(&mut form.value).password(true));
                            if resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                                save = true;
                            }
                            ui.end_row();
                        }
                        SecretKind::Key => {
                            ui.label("Private key");
                            ui.add(
                                egui::TextEdit::multiline(&mut form.value)
                                    .hint_text("Paste the PEM private key")
                                    .desired_rows(3),
                            );
                            ui.end_row();
                            ui.label("Passphrase");
                            ui.add(egui::TextEdit::singleline(&mut form.passphrase).password(true));
                            ui.end_row();
                        }
                    }
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save and connect").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        }
        if save {
            self.save_credential_and_connect(ctx);
        }
        if cancel {
            self.dialog = Dialog::None;
        }
    }

    /// Stores the prompted credential, then resumes connecting to its session.
    fn save_credential_and_connect(&mut self, ctx: &egui::Context) {
        let Dialog::CreateCredential(prompt) = &self.dialog else { return };
        if prompt.form.value.is_empty() {
            return self.set_credential_error("Enter the credential value.");
        }
        let name = prompt.form.name.clone();
        let secret = prompt.form.to_secret();
        let session = prompt.then_connect.clone();
        if let Err(e) = self.store_secret(&name, secret) {
            return self.set_credential_error(&e);
        }
        self.dialog = Dialog::None;
        self.start_connect(&session, ctx);
    }

    fn set_credential_error(&mut self, message: &str) {
        // Surfaced via the global error bar (the modal has no error line of its own).
        self.error = Some(message.to_owned());
    }

    fn show_unlock_vault(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::UnlockVault { password, remember, error } = &mut self.dialog {
            egui::Modal::new(egui::Id::new("unlock-vault")).show(ctx, |ui| {
                ui.set_width(320.0);
                ui.heading("Unlock vault");
                ui.add_space(6.0);
                let field = ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("Master password"),
                );
                autofocus(ui, &field);
                submit |= entered(ui, &field);
                ui.checkbox(remember, "Remember on this device")
                    .on_hover_text("Stores the key in your OS keyring so it unlocks automatically.");
                if let Some(error) = error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    submit |= ui.button("Unlock").clicked();
                    cancel |= ui.button("Cancel").clicked();
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
        let Dialog::UnlockVault { password, remember, error } = &mut self.dialog else { return };
        match Vault::open(self.vault_path.clone(), password) {
            Ok(vault) => {
                let remember = *remember;
                self.vault = VaultState::Unlocked(Box::new(vault));
                self.dialog = Dialog::None;
                self.apply_remember(remember);
            }
            Err(VaultError::BadPassword) => {
                *error = Some("Incorrect master password.".into());
            }
            Err(e) => *error = Some(format!("{e}")),
        }
    }

    /// Enables or disables keyring auto-unlock to match the "remember" choice.
    fn apply_remember(&mut self, remember: bool) {
        let result = if remember {
            self.vault.unlocked().map(|v| v.enable_keyring_unlock()).unwrap_or(Ok(()))
        } else {
            Vault::disable_keyring_unlock()
        };
        if let Err(e) = result {
            self.error = Some(format!("Could not update the saved password: {e:#}"));
        }
    }

    fn show_create_vault(&mut self, ctx: &egui::Context) {
        let mut submit = false;
        let mut cancel = false;
        if let Dialog::CreateVault { password, confirm, remember, error } = &mut self.dialog {
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
                let pw_field = ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("Master password"),
                );
                autofocus(ui, &pw_field);
                let confirm_field = ui.add(
                    egui::TextEdit::singleline(confirm)
                        .password(true)
                        .hint_text("Confirm password"),
                );
                submit |= entered(ui, &confirm_field);
                ui.checkbox(remember, "Remember on this device")
                    .on_hover_text("Stores the key in your OS keyring so it unlocks automatically.");
                if let Some(error) = error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    submit |= ui.button("Create").clicked();
                    cancel |= ui.button("Cancel").clicked();
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
        let Dialog::CreateVault { password, confirm, remember, error } = &mut self.dialog else {
            return;
        };
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
                let remember = *remember;
                self.vault = VaultState::Unlocked(Box::new(vault));
                self.dialog = Dialog::None;
                self.apply_remember(remember);
            }
            Err(e) => *error = Some(format!("{e:#}")),
        }
    }

    fn show_edit_session(&mut self, ctx: &egui::Context) {
        let mut save = false;
        let mut cancel = false;
        let secret_names = self.vault.unlocked().map(|v| v.names()).unwrap_or_default();
        let vault_unlocked = self.vault.unlocked().is_some();
        if let Dialog::EditSession(form) = &mut self.dialog {
            let title = if form.id.is_some() { "Edit session" } else { "New session" };
            egui::Modal::new(egui::Id::new("edit-session")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.heading(title);
                ui.add_space(6.0);
                // Enter in any single-line field submits the form.
                let mut enter = false;
                let mut line = |ui: &mut egui::Ui, value: &mut String, password: bool| {
                    let edit = egui::TextEdit::singleline(value).password(password);
                    let resp = ui.add(edit);
                    enter |= resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                };
                egui::Grid::new("session-fields").num_columns(2).show(ui, |ui| {
                    ui.label("Name");
                    line(ui, &mut form.name, false);
                    ui.end_row();
                    ui.label("Folder");
                    line(ui, &mut form.folder, false);
                    ui.end_row();
                    ui.label("Host");
                    line(ui, &mut form.host, false);
                    ui.end_row();
                    ui.label("Port");
                    line(ui, &mut form.port, false);
                    ui.end_row();
                    ui.label("Username");
                    line(ui, &mut form.username, false);
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

                    if form.method != AuthMethod::Agent {
                        ui.label("Credential");
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut form.source, SecretSource::Existing, "From vault");
                            ui.selectable_value(&mut form.source, SecretSource::New, "New");
                        });
                        ui.end_row();

                        match form.source {
                            SecretSource::Existing => {
                                ui.label("Vault entry");
                                let selected = form
                                    .existing_name
                                    .clone()
                                    .unwrap_or_else(|| "Choose…".into());
                                egui::ComboBox::from_id_salt("session-secret")
                                    .selected_text(selected)
                                    .show_ui(ui, |ui| {
                                        for name in &secret_names {
                                            ui.selectable_value(
                                                &mut form.existing_name,
                                                Some(name.clone()),
                                                name,
                                            );
                                        }
                                    });
                                ui.end_row();
                            }
                            SecretSource::New => {
                                ui.label("Save as");
                                line(ui, &mut form.new_name, false);
                                ui.end_row();
                                match form.method {
                                    AuthMethod::Password => {
                                        ui.label("Password");
                                        line(ui, &mut form.secret_input, true);
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
                                        line(ui, &mut form.key_passphrase, true);
                                        ui.end_row();
                                    }
                                    AuthMethod::Agent => {}
                                }
                            }
                        }
                    }
                });
                ui.add_space(4.0);
                ui.checkbox(&mut form.legacy, "Legacy mode (old switches: SHA-1 KEX, CBC ciphers)")
                    .on_hover_text(
                        "Enables weak but widely compatible algorithms. Use only for old \
                         equipment such as HPE/ProCurve switches.",
                    );
                ui.add_space(4.0);
                appearance_picker(ui, &mut form.icon, &mut form.color, "🖥");
                if form.method != AuthMethod::Agent && !vault_unlocked {
                    ui.colored_label(
                        Color32::LIGHT_YELLOW,
                        "Unlock or create the vault to use saved credentials.",
                    );
                }
                if let Some(error) = &form.error {
                    ui.colored_label(Color32::LIGHT_RED, error.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() || enter {
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
        let (id, name, folder, host, port_str, username, method, legacy) = (
            form.id.clone(),
            form.name.trim().to_owned(),
            form.folder.trim().to_owned(),
            form.host.trim().to_owned(),
            form.port.trim().to_owned(),
            form.username.trim().to_owned(),
            form.method,
            form.legacy,
        );
        let (icon, color) = (form.icon.clone(), form.color);
        let (source, existing_name, new_name, secret_input, key_passphrase) = (
            form.source,
            form.existing_name.clone(),
            form.new_name.trim().to_owned(),
            form.secret_input.clone(),
            form.key_passphrase.clone(),
        );
        let target = form.target.clone();

        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return self.set_form_error("Port must be a number."),
        };
        if host.is_empty() {
            return self.set_form_error("A host is required.");
        }

        // Build the session, reusing the id when editing so a default vault name is stable.
        let mut session = Session::new(&name, &host, &username);
        if let Some(id) = id {
            session.id = id;
        }
        session.folder = folder;
        session.port = port;
        session.legacy = legacy;
        session.icon = icon;
        session.color = color;

        // Agent auth needs no stored secret.
        session.auth = if method == AuthMethod::Agent {
            Auth::Agent
        } else {
            // Resolve the vault entry name this session should reference. An empty
            // name (blank password, no existing entry) means "prompt every time".
            let secret_name = match source {
                SecretSource::Existing => match existing_name {
                    Some(n) => n,
                    None => return self.set_form_error("Choose a vault entry, or switch to New."),
                },
                SecretSource::New => {
                    let secret_name = if new_name.is_empty() {
                        self.default_secret_name(&name, &host)
                    } else {
                        new_name
                    };
                    if !secret_input.is_empty() {
                        // Store the session's username with the credential.
                        let cred_user = (!username.is_empty()).then(|| username.clone());
                        let secret = match method {
                            AuthMethod::Password => {
                                Secret::Password { username: cred_user, password: secret_input }
                            }
                            AuthMethod::Key => Secret::PrivateKey {
                                pem: secret_input,
                                passphrase: (!key_passphrase.is_empty()).then_some(key_passphrase),
                                username: cred_user,
                            },
                            AuthMethod::Agent => unreachable!("agent handled above"),
                        };
                        if let Err(e) = self.store_secret(&secret_name, secret) {
                            return self.set_form_error(&e);
                        }
                        secret_name
                    } else if self.vault.unlocked().and_then(|v| v.get(&secret_name)).is_some() {
                        // Keep referencing the existing entry.
                        secret_name
                    } else if method == AuthMethod::Password {
                        // Blank password with no entry: prompt at connect time.
                        String::new()
                    } else {
                        return self.set_form_error(
                            "Enter the private key, or choose an existing vault entry.",
                        );
                    }
                }
            };
            match method {
                AuthMethod::Password => Auth::Password { secret: secret_name },
                AuthMethod::Key => Auth::Key { secret: secret_name },
                AuthMethod::Agent => unreachable!("agent handled above"),
            }
        };

        if let Err(e) = self.store_upsert(&target, session) {
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

    /// A readable, unique vault-entry name derived from the session name (or
    /// host), de-duplicated against existing entries (`prod`, `prod-2`, …).
    fn default_secret_name(&self, session_name: &str, host: &str) -> String {
        let mut base = slugify(session_name);
        if base.is_empty() {
            base = slugify(host);
        }
        if base.is_empty() {
            base = "credential".into();
        }
        let existing: Vec<String> = self.vault.unlocked().map(|v| v.names()).unwrap_or_default();
        if !existing.contains(&base) {
            return base;
        }
        (2..).map(|n| format!("{base}-{n}")).find(|c| !existing.contains(c)).unwrap_or(base)
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
            self.reject_host_key();
        }
    }

    /// Records the host key as trusted and retries the originating tab.
    fn trust_and_reconnect(&mut self, ctx: &egui::Context) {
        let Dialog::HostKey { info, tab_id, .. } =
            std::mem::replace(&mut self.dialog, Dialog::None)
        else {
            return;
        };
        if let Err(e) = trust_host(&info.host, info.port, &info.key_openssh) {
            self.error = Some(format!("Could not record the host key: {e:#}"));
            return;
        }
        self.retry_tab(tab_id, ctx);
    }

    /// Dismisses the host-key prompt, marking the originating tab as failed.
    fn reject_host_key(&mut self) {
        let Dialog::HostKey { tab_id, .. } = std::mem::replace(&mut self.dialog, Dialog::None)
        else {
            return;
        };
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id)
            && let TabContent::Connecting(c) = &mut tab.content
        {
            c.status = "Cancelled".into();
            c.error = Some("Host key was not trusted.".into());
        }
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
                        autofocus(ui, &field);
                        connect |= entered(ui, &field);
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
            GenerateOpen,
            GenerateRun,
            GenerateCancel,
            DismissPublic,
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

                if let Some(gf) = &mut state.gen_form {
                    ui.heading("Generate key pair");
                    ui.label(RichText::new("Creates an Ed25519 key and stores the private key here.").weak());
                    egui::Grid::new("gen-fields").num_columns(2).show(ui, |ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(&mut gf.name);
                        ui.end_row();
                        ui.label("Comment");
                        ui.add(egui::TextEdit::singleline(&mut gf.comment).hint_text("user@host (optional)"));
                        ui.end_row();
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("Generate").clicked() {
                            action = Action::GenerateRun;
                        }
                        if ui.button("Cancel").clicked() {
                            action = Action::GenerateCancel;
                        }
                    });
                } else if let Some((name, public)) = state.last_public.clone() {
                    ui.heading("Key pair created");
                    ui.label(format!("Stored private key as '{name}'. Public key:"));
                    ui.add_space(4.0);
                    let mut public_text = public.clone();
                    ui.add(egui::TextEdit::multiline(&mut public_text).desired_rows(3).font(egui::TextStyle::Monospace));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button("Copy public key").clicked() {
                            ui.ctx().copy_text(public);
                        }
                        if ui.button("Done").clicked() {
                            action = Action::DismissPublic;
                        }
                    });
                } else {
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
                            if ui.button("Generate key pair").clicked() {
                                action = Action::GenerateOpen;
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
                            ui.label("Username");
                            ui.add(
                                egui::TextEdit::singleline(&mut form.username)
                                    .hint_text("(optional, overrides session)"),
                            );
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
            Action::GenerateOpen => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.gen_form = Some(GenForm::default());
                    state.error = None;
                }
            }
            Action::GenerateCancel => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.gen_form = None;
                    state.error = None;
                }
            }
            Action::GenerateRun => self.generate_keypair(),
            Action::DismissPublic => {
                if let Dialog::VaultManager(state) = &mut self.dialog {
                    state.last_public = None;
                }
            }
        }
    }

    /// Generates an Ed25519 key pair, stores the private key, and shows the public key.
    fn generate_keypair(&mut self) {
        let Dialog::VaultManager(state) = &self.dialog else { return };
        let Some(gf) = &state.gen_form else { return };
        let name = gf.name.trim().to_owned();
        let comment = gf.comment.trim().to_owned();
        if name.is_empty() {
            return self.set_vault_error("Name is required.");
        }
        if self.vault.unlocked().and_then(|v| v.get(&name)).is_some() {
            return self.set_vault_error("A secret with that name already exists.");
        }
        let generated = match wazowski_ssh::generate_ed25519(&comment) {
            Ok(k) => k,
            Err(e) => return self.set_vault_error(&format!("{e:#}")),
        };
        let secret =
            Secret::PrivateKey { pem: generated.private_pem, passphrase: None, username: None };
        if let Err(e) = self.store_secret(&name, secret) {
            return self.set_vault_error(&e);
        }
        if let Dialog::VaultManager(state) = &mut self.dialog {
            state.gen_form = None;
            state.error = None;
            state.last_public = Some((name, generated.public_openssh));
        }
    }

    /// Loads an existing secret into the manager's edit form (values left blank
    /// so they are only overwritten when the user types a new value).
    fn begin_edit_secret(&mut self, name: &str) {
        let (kind, username) = match self.vault.unlocked().and_then(|v| v.get(name)) {
            Some(secret @ Secret::Password { .. }) => {
                (SecretKind::Password, secret.username().unwrap_or_default().to_owned())
            }
            Some(secret @ Secret::PrivateKey { .. }) => {
                (SecretKind::Key, secret.username().unwrap_or_default().to_owned())
            }
            None => return,
        };
        if let Dialog::VaultManager(state) = &mut self.dialog {
            state.form = Some(SecretForm {
                original: Some(name.to_owned()),
                name: name.to_owned(),
                kind,
                username,
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
        let secret = form.to_secret();
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

        // Confirm before closing the window while sessions/shells are open.
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            if self.tabs.is_empty() {
                self.quitting = true;
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                if !matches!(self.dialog, Dialog::ConfirmQuit) {
                    self.dialog = Dialog::ConfirmQuit;
                }
            }
        }

        // Periodically re-read shared sources so others' changes appear.
        if !self.shared.is_empty() {
            const SYNC_EVERY: std::time::Duration = std::time::Duration::from_secs(20);
            if self.last_sync.elapsed() >= SYNC_EVERY {
                for source in &mut self.shared {
                    source.reload();
                }
                self.last_sync = std::time::Instant::now();
            }
            ctx.request_repaint_after(SYNC_EVERY);
        }

        // A borrowed session (shown in another tab's split) that has exited
        // returns to its own tab, which then shows the "ended" banner with the
        // restart / save / close options — just like ending in its own tab.
        for i in 0..self.tabs.len() {
            let exited = match &self.tabs[i].content {
                TabContent::Terminal(panes) => panes.exited_moved(),
                _ => Vec::new(),
            };
            for id in exited {
                let taken = match &mut self.tabs[i].content {
                    TabContent::Terminal(panes) => panes.remove_leaf(id),
                    _ => None,
                };
                if let Some((term, Some(home))) = taken {
                    self.return_home(home, term);
                }
            }
        }

        // If a split tab's own (origin) session has exited, collapse the split
        // down to just that session (returning borrowed panes home), so the tab
        // shows the "ended" banner and can still save the original's output.
        for i in 0..self.tabs.len() {
            let collapse = match (self.tabs[i].origin_term, &self.tabs[i].content) {
                (Some(origin), TabContent::Terminal(panes)) => {
                    panes.count() > 1 && panes.get(origin).is_some_and(|t| t.has_exited())
                }
                _ => false,
            };
            if collapse
                && let Some(origin) = self.tabs[i].origin_term
            {
                let others = match &mut self.tabs[i].content {
                    TabContent::Terminal(panes) => panes.keep_only(origin),
                    _ => Vec::new(),
                };
                for (term, home) in others {
                    if let Some(home) = home {
                        self.return_home(home, term);
                    }
                }
            }
        }

        // Drop individual panes whose shell exited. Leave a fully-exited tab's
        // panes in place so an SSH/serial tab can show its "ended" banner and
        // still save its buffer; local shells are auto-closed below.
        for tab in &mut self.tabs {
            if let TabContent::Terminal(panes) = &mut tab.content
                && !panes.all_exited()
            {
                panes.prune();
            }
        }
        // If a tab's own (origin) session has been closed/removed, send any
        // sessions it borrowed into split panes back to their home tabs.
        for i in 0..self.tabs.len() {
            let origin_gone = match (self.tabs[i].origin_term, &self.tabs[i].content) {
                (Some(origin), TabContent::Terminal(panes)) => !panes.ids().contains(&origin),
                _ => false,
            };
            if origin_gone {
                let moved = match &mut self.tabs[i].content {
                    TabContent::Terminal(panes) => panes.drain_moved(),
                    _ => Vec::new(),
                };
                for (term, home) in moved {
                    self.return_home(home, term);
                }
            }
        }

        // Close dead tabs via close_tab so any moved-in sessions return home. An
        // emptied terminal tab (no panes left) is always closed; a tab whose
        // terminal is present but exited stays for its "ended" banner.
        let mut i = 0;
        while i < self.tabs.len() {
            let dead = match &self.tabs[i].content {
                TabContent::Terminal(panes) => {
                    panes.count() == 0
                        || (panes.all_exited()
                            && !self.tabs[i].restart.as_ref().is_some_and(RestartKind::keep_open))
                }
                _ => false,
            };
            if dead {
                self.close_tab(i);
            } else {
                i += 1;
            }
        }

        self.poll_connections(&ctx);
        self.poll_admin(&ctx);
        if self.settings.auto_backup_due() && Vault::exists(&self.vault_path) {
            self.run_vault_backup(false);
        }
        // Refresh the serial device list for the sidebar every few seconds.
        if self.serial_ports_at.elapsed() >= std::time::Duration::from_secs(3) {
            self.serial_ports = sorted_serial_devices();
            self.serial_ports_at = std::time::Instant::now();
        }
        // Keep server logs flowing and repaint while any server runs.
        if self.poll_servers() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
        // Suppress tab shortcuts while a modal is open so typing a password
        // doesn't also switch tabs.
        if matches!(self.dialog, Dialog::None) {
            self.shortcuts(&ctx);
        }
        // Drive any running macro, and let Esc cancel it.
        if self.macro_run.is_some() {
            if matches!(self.dialog, Dialog::None) && ctx.input(|i| i.key_pressed(Key::Escape)) {
                self.macro_run = None;
            } else {
                self.advance_macro(&ctx);
            }
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
        if let Some(run) = &self.macro_run {
            let status = format!(
                "▶ Running macro \"{}\" — step {}/{}",
                run.name,
                (run.index + 1).min(run.steps.len()),
                run.steps.len()
            );
            let mut cancel = false;
            egui::Panel::bottom("macro-status").show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(status);
                    if ui.small_button("Cancel").clicked() {
                        cancel = true;
                    }
                    ui.label(RichText::new("(Esc to cancel)").weak());
                });
            });
            if cancel {
                self.macro_run = None;
            }
        }
        // The SFTP browser now lives in the left pane's "Files" view (see sidebar).
        // Persist a changed SFTP auto-refresh toggle back to the saved session.
        let pref = self.tabs.get(self.active).and_then(|t| {
            Some((t.session_id.clone()?, t.files.as_ref()?.auto_refresh()))
        });
        if let Some((sid, current)) = pref
            && let Some((store, mut session)) = self.find_session_anywhere(&sid)
            && session.sftp_auto_refresh != current
        {
            session.sftp_auto_refresh = current;
            let _ = self.store_upsert(&store, session);
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
            method: AuthMethod::Password,
            source: SecretSource::New,
            existing_name: None,
            new_name: String::new(),
            secret_input: String::new(),
            key_passphrase: String::new(),
            legacy: false,
            icon: String::new(),
            color: None,
            error: None,
            target: StoreId::Local,
        }
    }

    fn from_session(session: &Session) -> Self {
        // An existing session already references a named vault entry, so default
        // to reusing it (and preselect the name).
        let (method, existing_name) = match &session.auth {
            Auth::Agent => (AuthMethod::Agent, None),
            Auth::Password { secret } => (AuthMethod::Password, Some(secret.clone())),
            Auth::Key { secret } => (AuthMethod::Key, Some(secret.clone())),
        };
        Self {
            id: Some(session.id.clone()),
            name: session.name.clone(),
            folder: session.folder.clone(),
            host: session.host.clone(),
            port: session.port.to_string(),
            username: session.username.clone(),
            method,
            source: if existing_name.is_some() { SecretSource::Existing } else { SecretSource::New },
            existing_name,
            new_name: String::new(),
            secret_input: String::new(),
            key_passphrase: String::new(),
            legacy: session.legacy,
            icon: session.icon.clone(),
            color: session.color,
            error: None,
            target: StoreId::Local,
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

/// An action chosen from the session tree, applied after rendering.
#[derive(Clone)]
enum TreeAction {
    Connect(StoreId, String),
    ConnectAs(StoreId, String),
    OpenWebGui(StoreId, String),
    NetworkTool(StoreId, String, NetTool),
    Edit(StoreId, String),
    Delete(StoreId, String),
    Duplicate(StoreId, String),
    MoveTo { from: StoreId, id: String, to: StoreId, folder: String },
    CopyTo { from: StoreId, id: String, to: StoreId, folder: String },
    MoveFolder { from: StoreId, folder: String, to: StoreId, parent: String },
    CopyFolder { from: StoreId, folder: String, to: StoreId, parent: String },
    NewSessionIn(StoreId, String),
    NewFolderIn(StoreId, String),
    RenameFolder(StoreId, String),
    FolderAppearance(StoreId, String),
    DeleteFolder(StoreId, String),
    SyncSource(String),
    OpenSource(String),
    EditSource(String),
    RemoveSource(String),
    /// A drag-and-drop release onto a folder (or root) of a destination store.
    Dropped { payload: DragPayload, to: StoreId, folder: String },
}

/// Renders one store's folders and sessions, emitting a [`TreeAction`] on
/// interaction. `editable` is false for an offline shared source (view only).
/// A node in the folder tree built from folder paths and session locations.
#[derive(Default)]
struct FolderNode {
    children: BTreeMap<String, FolderNode>,
    /// Each session directly in this folder.
    sessions: Vec<SessionRow>,
}

/// A session's data needed to render its sidebar row.
struct SessionRow {
    id: String,
    name: String,
    hint: String,
    icon: String,
    color: Option<[u8; 3]>,
}

impl FolderNode {
    /// Descends to (creating as needed) the node for a `/`-separated path.
    fn at(&mut self, path: &str) -> &mut FolderNode {
        let mut node = self;
        if !path.is_empty() {
            for segment in path.split('/') {
                node = node.children.entry(segment.to_owned()).or_default();
            }
        }
        node
    }
}

/// A move/copy destination: a store and its folders.
struct Destination {
    store: StoreId,
    label: String,
    folders: Vec<String>,
}

fn render_store(
    ui: &mut egui::Ui,
    store: &StoreId,
    sessions: &SessionStore,
    editable: bool,
    destinations: &[Destination],
    action: &mut Option<TreeAction>,
) {
    // Build a nested tree; folder paths synthesize their ancestor nodes.
    let folders = sessions.folders();
    let mut root = FolderNode::default();
    for folder in &folders {
        root.at(folder);
    }
    for session in sessions.all() {
        root.at(&session.folder).sessions.push(SessionRow {
            id: session.id.clone(),
            name: session.name.clone(),
            hint: session_hint(session),
            icon: session.icon.clone(),
            color: session.color,
        });
    }

    // Root-level sessions, then each top-level folder recursively.
    for row in &root.sessions {
        session_row(ui, store, row, destinations, editable, action);
    }
    let children: Vec<_> = root.children.iter().collect();
    for (segment, node) in children {
        render_folder(ui, store, sessions, segment, segment, node, destinations, editable, action);
    }
}

/// Recursively renders one folder node (a collapsible header with its sessions
/// and subfolders). `full` is the folder's full `/`-separated path.
#[allow(clippy::too_many_arguments)]
fn render_folder(
    ui: &mut egui::Ui,
    store: &StoreId,
    data: &SessionStore,
    segment: &str,
    full: &str,
    node: &FolderNode,
    destinations: &[Destination],
    editable: bool,
    action: &mut Option<TreeAction>,
) {
    use egui::containers::collapsing_header::CollapsingState;

    let id = egui::Id::new((store_salt(store), "folder", full));
    let state = CollapsingState::load_with_default_open(ui.ctx(), id, true);
    let style = data.folder_style(full);
    let icon = style.map(|s| s.icon.as_str()).filter(|i| !i.is_empty()).unwrap_or("📁");
    let text = {
        let t = RichText::new(format!("{icon} {segment}"));
        match style.and_then(|s| s.color) {
            Some([r, g, b]) => t.color(Color32::from_rgb(r, g, b)),
            None => t,
        }
    };
    // Header: a draggable folder label next to the collapse triangle.
    let (_toggle, header_inner, _body) = state
        .show_header(ui, |ui| {
            drag_label(
                ui,
                text,
                DragPayload::Folder { store: store.clone(), path: full.to_owned() },
            )
        })
        .body(|ui| {
            for row in &node.sessions {
                session_row(ui, store, row, destinations, editable, action);
            }
            for (child_segment, child) in &node.children {
                let child_full = format!("{full}/{child_segment}");
                render_folder(
                    ui, store, data, child_segment, &child_full, child, destinations, editable,
                    action,
                );
            }
        });

    // The header row is a drop target for sessions/folders dragged onto it.
    let header_row = header_inner.response;
    // The menu goes on the label (the hit widget), not the whole row, so a
    // right-click on the folder name actually opens it.
    let header_label = header_inner.inner;
    if editable
        && let Some(payload) = header_row.dnd_release_payload::<DragPayload>()
    {
        *action = Some(TreeAction::Dropped {
            payload: (*payload).clone(),
            to: store.clone(),
            folder: full.to_owned(),
        });
    }
    if editable {
        header_label.context_menu(|ui| {
            if ui.button("New session here").clicked() {
                *action = Some(TreeAction::NewSessionIn(store.clone(), full.to_owned()));
                ui.close();
            }
            if ui.button("New subfolder").clicked() {
                *action = Some(TreeAction::NewFolderIn(store.clone(), full.to_owned()));
                ui.close();
            }
            if ui.button("Rename folder").clicked() {
                *action = Some(TreeAction::RenameFolder(store.clone(), full.to_owned()));
                ui.close();
            }
            if ui.button("Appearance…").clicked() {
                *action = Some(TreeAction::FolderAppearance(store.clone(), full.to_owned()));
                ui.close();
            }
            // Move/copy the whole folder (subfolders and sessions included).
            destination_menu(ui, "Move folder to", destinations, |to, parent| {
                *action = Some(TreeAction::MoveFolder {
                    from: store.clone(),
                    folder: full.to_owned(),
                    to,
                    parent,
                });
            });
            destination_menu(ui, "Copy folder to", destinations, |to, parent| {
                *action = Some(TreeAction::CopyFolder {
                    from: store.clone(),
                    folder: full.to_owned(),
                    to,
                    parent,
                });
            });
            ui.separator();
            if ui.button("Delete folder").clicked() {
                *action = Some(TreeAction::DeleteFolder(store.clone(), full.to_owned()));
                ui.close();
            }
        });
    }
}

/// A label that can be dragged (setting `payload`) while still reporting clicks
/// and right-clicks. Uses egui's `dnd_set_drag_payload`, which only begins a drag
/// after the pointer moves — so a stationary right-click still opens the context
/// menu. Returns the response for click/menu handling.
fn drag_label(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    payload: DragPayload,
) -> egui::Response {
    let resp = ui.add(egui::Button::new(text).frame(false).sense(egui::Sense::click_and_drag()));
    resp.dnd_set_drag_payload(payload);
    resp
}

/// Whether a drop is a no-op or invalid (dropping a folder into itself/subtree).
fn is_noop_drop(payload: &DragPayload, to: &StoreId, folder: &str) -> bool {
    match payload {
        // A session drop always offers a choice (copy is useful even in place).
        DragPayload::Session { .. } => false,
        DragPayload::Folder { store, path } => {
            if store != to {
                return false;
            }
            let base = path.rsplit('/').next().unwrap_or(path);
            let new = if folder.is_empty() { base.to_owned() } else { format!("{folder}/{base}") };
            // Same spot, into itself, or into its own subtree.
            new == *path || folder == path || folder.starts_with(&format!("{path}/"))
        }
    }
}

/// A brief description of a shared source, for its left-pane hover tooltip.
fn source_hint(def: &SourceDef) -> String {
    match def.kind {
        SourceKind::Folder => format!("Shared folder\nfile: {}", def.path.display()),
        SourceKind::Git => {
            let branch = if def.branch.is_empty() { "(default)" } else { &def.branch };
            let repo = def.url.rsplit('/').next().unwrap_or(&def.url).trim_end_matches(".git");
            format!("Git repo: {repo}\nurl: {}\nbranch: {branch}\nfile: {}", def.url, def.file)
        }
    }
}

/// A brief description of a session, for its left-pane hover tooltip.
fn session_hint(s: &Session) -> String {
    let auth = match &s.auth {
        Auth::Agent => "SSH agent",
        Auth::Password { .. } => "password",
        Auth::Key { .. } => "key",
    };
    let mut hint = format!("SSH · {}\nauth: {auth}", s.address());
    if s.legacy {
        hint.push_str("\nlegacy algorithms");
    }
    hint
}

/// Shows a tooltip on `response`, but only once the pointer has rested on the
/// widget for a few seconds, so hovering the left pane isn't noisy.
fn delayed_tooltip(ui: &egui::Ui, response: &egui::Response, text: &str) {
    const DELAY: f64 = 1.5;
    if text.is_empty() {
        return;
    }
    let id = response.id.with("wz-hover-since");
    if response.hovered() {
        let now = ui.input(|i| i.time);
        let since: f64 = ui.data_mut(|d| *d.get_temp_mut_or_insert_with(id, || now));
        if now - since >= DELAY {
            response.clone().on_hover_text(text);
        } else {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
        }
    } else {
        ui.data_mut(|d| d.remove::<f64>(id));
    }
}

/// A stable salt per store so folder headers in different stores don't collide.
fn store_salt(store: &StoreId) -> String {
    match store {
        StoreId::Local => "local".into(),
        StoreId::Shared(id) => format!("shared:{id}"),
    }
}

/// Renders one session row: double-click connects, right-click opens its menu.
fn session_row(
    ui: &mut egui::Ui,
    store: &StoreId,
    row: &SessionRow,
    destinations: &[Destination],
    editable: bool,
    action: &mut Option<TreeAction>,
) {
    let (id, name) = (row.id.as_str(), row.name.as_str());
    let icon = if row.icon.is_empty() { "🖥" } else { row.icon.as_str() };
    let text = {
        let t = RichText::new(format!("{icon} {name}"));
        match row.color {
            Some([r, g, b]) => t.color(Color32::from_rgb(r, g, b)),
            None => t,
        }
    };
    // The row drags with the primary button; right-click still opens the menu.
    let resp = drag_label(ui, text, DragPayload::Session { store: store.clone(), id: id.to_owned() });
    delayed_tooltip(ui, &resp, &row.hint);
    if resp.double_clicked() {
        *action = Some(TreeAction::Connect(store.clone(), id.to_owned()));
    }
    resp.context_menu(|ui| {
        if ui.button("Connect").clicked() {
            *action = Some(TreeAction::Connect(store.clone(), id.to_owned()));
            ui.close();
        }
        if ui.button("Connect as…").clicked() {
            *action = Some(TreeAction::ConnectAs(store.clone(), id.to_owned()));
            ui.close();
        }
        if ui.button("Open web GUI").clicked() {
            *action = Some(TreeAction::OpenWebGui(store.clone(), id.to_owned()));
            ui.close();
        }
        ui.menu_button("Network tools", |ui| {
            for (label, tool) in [
                ("Ping", NetTool::Ping),
                ("Port scan (common)", NetTool::PortScanCommon),
                ("Port scan (1-1024)", NetTool::PortScanWellKnown),
                ("Scan subnet (/24)", NetTool::SubnetScan),
            ] {
                if ui.button(label).clicked() {
                    *action = Some(TreeAction::NetworkTool(store.clone(), id.to_owned(), tool));
                    ui.close();
                }
            }
        });
        if editable {
            if ui.button("Edit…").clicked() {
                *action = Some(TreeAction::Edit(store.clone(), id.to_owned()));
                ui.close();
            }
            if ui.button("Duplicate").clicked() {
                *action = Some(TreeAction::Duplicate(store.clone(), id.to_owned()));
                ui.close();
            }
            // Move/Copy to a store + folder. A single destination collapses the
            // store level; multiple destinations nest store → folder.
            destination_menu(ui, "Move to", destinations, |to, folder| {
                *action = Some(TreeAction::MoveTo {
                    from: store.clone(),
                    id: id.to_owned(),
                    to,
                    folder,
                });
            });
            destination_menu(ui, "Copy to", destinations, |to, folder| {
                *action = Some(TreeAction::CopyTo {
                    from: store.clone(),
                    id: id.to_owned(),
                    to,
                    folder,
                });
            });
            ui.separator();
            if ui.button("Delete").clicked() {
                *action = Some(TreeAction::Delete(store.clone(), id.to_owned()));
                ui.close();
            }
        }
    });
}

/// Builds the URL for a session's web management page. If the host already
/// carries a scheme it is used as-is; otherwise the configured scheme is
/// prepended. Any trailing slash in the host is trimmed.
fn web_gui_url(host: &str, scheme: WebScheme) -> String {
    let host = host.trim().trim_end_matches('/');
    if host.starts_with("http://") || host.starts_with("https://") {
        host.to_owned()
    } else {
        format!("{}{host}", scheme.prefix())
    }
}

/// A nested "Move to / Copy to" menu over destinations (store → folder).
fn destination_menu(
    ui: &mut egui::Ui,
    label: &str,
    destinations: &[Destination],
    mut chosen: impl FnMut(StoreId, String),
) {
    ui.menu_button(label, |ui| {
        for dest in destinations {
            ui.menu_button(&dest.label, |ui| {
                if ui.button("(root)").clicked() {
                    chosen(dest.store.clone(), String::new());
                    ui.close();
                }
                for folder in &dest.folders {
                    if ui.button(folder).clicked() {
                        chosen(dest.store.clone(), folder.clone());
                        ui.close();
                    }
                }
            });
        }
    });
}

/// Turns a display string into a lowercase `a-z0-9-` slug.
fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// Converts a stored secret into connect-ready auth material.
fn material_from(secret: &Secret) -> AuthMaterial {
    match secret {
        Secret::Password { password, .. } => AuthMaterial::Password(password.clone()),
        Secret::PrivateKey { pem, passphrase, .. } => {
            AuthMaterial::Key { pem: pem.clone(), passphrase: passphrase.clone() }
        }
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

/// Renders a connecting tab (status, live log, and Retry/Copy on failure).
/// Returns the tab id if the user asked to retry.
fn connecting_view(ui: &mut egui::Ui, c: &Connecting, tab_id: u64) -> Option<u64> {
    let mut retry = None;
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if c.error.is_none() {
            ui.spinner();
        }
        ui.heading(&c.title);
    });
    ui.label(RichText::new(&c.status).weak());
    if let Some(error) = &c.error {
        ui.add_space(4.0);
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if c.error.is_some() && ui.button("Retry").clicked() {
            retry = Some(tab_id);
        }
        if ui.button("Copy log").on_hover_text("Copy the handshake log").clicked() {
            ui.ctx().copy_text(c.log.join("\n"));
        }
    });
    ui.separator();

    // The handshake log, newest at the bottom.
    egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
        for line in &c.log {
            ui.label(RichText::new(line).monospace().size(11.0));
        }
    });
    retry
}

/// Requests focus for a field only when nothing else is focused, so auto-focus
/// works on first open without stealing focus every frame (which would break
/// Enter-to-submit, since the field would never register as losing focus).
fn autofocus(ui: &egui::Ui, resp: &egui::Response) {
    // Don't re-grab on the frame the field surrendered focus (Enter): doing so
    // would clear `lost_focus`, which is how we detect the Enter submit.
    if !resp.lost_focus() && ui.memory(|m| m.focused().is_none()) {
        resp.request_focus();
    }
}

/// True if Enter was pressed to submit this single-line field.
fn entered(ui: &egui::Ui, resp: &egui::Response) -> bool {
    resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// A menu button that shows its keyboard shortcut; returns whether it was clicked.
/// Keys not allowed as a shortcut's main key. egui reports Ctrl/Alt/Shift via
/// `Modifiers` rather than as `Key`s, so only Escape needs excluding here (it
/// cancels capture instead of becoming a binding).
fn is_modifier_key(key: Key) -> bool {
    matches!(key, Key::Escape)
}

/// Counts non-overlapping occurrences of `needle` in `hay`.
fn count_occurrences(hay: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut rest = hay;
    while let Some(pos) = rest.find(needle) {
        count += 1;
        rest = &rest[pos + needle.len()..];
    }
    count
}

/// Emoji icons offered for sessions and folders.
const ICON_CHOICES: &[&str] = &[
    "🖥", "💻", "🌐", "🔀", "🗄", "🔒", "🛡", "📡", "🖨", "☁", "⚡", "🔌", "📶", "🧱", "🐧", "🪟",
    "🍎", "🔧", "🚦", "📦",
];

/// An icon (emoji) + optional color picker row, shared by sessions and folders.
/// `default_icon` is shown as the "no custom icon" choice.
fn appearance_picker(
    ui: &mut egui::Ui,
    icon: &mut String,
    color: &mut Option<[u8; 3]>,
    default_icon: &str,
) {
    ui.horizontal(|ui| {
        ui.label("Icon:");
        egui::ComboBox::from_id_salt("icon-pick")
            .selected_text(if icon.is_empty() { default_icon } else { icon.as_str() })
            .show_ui(ui, |ui| {
                if ui.selectable_label(icon.is_empty(), format!("{default_icon} (default)")).clicked()
                {
                    icon.clear();
                }
                for choice in ICON_CHOICES {
                    if ui.selectable_label(icon == choice, *choice).clicked() {
                        *icon = (*choice).to_owned();
                    }
                }
            });
        ui.label("Color:");
        let mut rgb = color.unwrap_or([200, 200, 200]);
        if ui.color_edit_button_srgb(&mut rgb).changed() {
            *color = Some(rgb);
        }
        if color.is_some() && ui.small_button("✕").on_hover_text("Clear color").clicked() {
            *color = None;
        }
    });
}

/// Writes `text` to a temp file and prints it via the platform's print command
/// (CUPS `lp`/`lpr` on Unix, Notepad `/p` on Windows).
fn print_text(text: &str) -> std::io::Result<()> {
    let path = std::env::temp_dir().join(format!("wazowski-print-{}.txt", std::process::id()));
    std::fs::write(&path, text)?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        std::process::Command::new("notepad.exe")
            .arg("/p")
            .arg(&path)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let status = std::process::Command::new("lp")
            .arg(&path)
            .status()
            .or_else(|_| std::process::Command::new("lpr").arg(&path).status())?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("the print command failed (is CUPS/lp installed?)"))
        }
    }
}

/// Formats an elapsed duration compactly (e.g. `3m 12s`, `1h 4m`).
fn fmt_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3_600 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}h {}m", s / 3_600, (s % 3_600) / 60)
    }
}

/// A coarse "N units ago" description of a past time, dependency-free.
fn time_ago(when: std::time::SystemTime) -> String {
    let Ok(elapsed) = when.elapsed() else { return "just now".to_owned() };
    let secs = elapsed.as_secs();
    if secs < 60 {
        "moments ago".to_owned()
    } else if secs < 3_600 {
        format!("{} minute(s) ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} hour(s) ago", secs / 3_600)
    } else {
        format!("{} day(s) ago", secs / 86_400)
    }
}

/// One row of the macro editor: a kind picker plus that kind's fields.
fn step_editor(ui: &mut egui::Ui, step: &mut Step) {
    let labels = ["Type text", "Press key", "Wait for", "Delay"];
    let mut kind = match step {
        Step::Text { .. } => 0,
        Step::Key { .. } => 1,
        Step::Expect { .. } => 2,
        Step::Delay { .. } => 3,
    };
    let before = kind;
    egui::ComboBox::from_id_salt("step-kind").width(96.0).selected_text(labels[kind]).show_ui(
        ui,
        |ui| {
            for (i, label) in labels.iter().enumerate() {
                ui.selectable_value(&mut kind, i, *label);
            }
        },
    );
    if kind != before {
        *step = match kind {
            0 => Step::Text { text: String::new(), enter: true },
            1 => Step::Key { chord: "Enter".to_owned() },
            2 => Step::Expect { text: String::new(), timeout_ms: 10_000 },
            _ => Step::Delay { ms: 500 },
        };
    }
    match step {
        Step::Text { text, enter } => {
            ui.text_edit_singleline(text);
            ui.checkbox(enter, "⏎").on_hover_text("Append Enter");
        }
        Step::Key { chord } => {
            ui.text_edit_singleline(chord)
                .on_hover_text("e.g. Enter, Tab, Ctrl+C, Up, Esc");
        }
        Step::Expect { text, timeout_ms } => {
            ui.text_edit_singleline(text);
            let mut secs = (*timeout_ms / 1000).max(1);
            ui.add(egui::DragValue::new(&mut secs).range(1..=600).suffix(" s"));
            *timeout_ms = secs * 1000;
        }
        Step::Delay { ms } => {
            ui.add(egui::DragValue::new(ms).range(0..=600_000).suffix(" ms"));
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_gui_url_prepends_configured_scheme() {
        assert_eq!(web_gui_url("10.0.0.1", WebScheme::Https), "https://10.0.0.1");
        assert_eq!(web_gui_url("switch.lan", WebScheme::Http), "http://switch.lan");
    }

    #[test]
    fn web_gui_url_respects_existing_scheme_and_trims() {
        assert_eq!(web_gui_url("http://10.0.0.1", WebScheme::Https), "http://10.0.0.1");
        assert_eq!(web_gui_url("https://nas:8443", WebScheme::Http), "https://nas:8443");
        assert_eq!(web_gui_url("  10.0.0.1/  ", WebScheme::Https), "https://10.0.0.1");
    }
}
