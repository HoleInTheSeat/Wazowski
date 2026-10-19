# Wazowski — Plan

A MobaXterm-style terminal and remote-session toolbox, written entirely in Rust.
Primary target: Fedora Linux. Also intended to run on Windows and macOS.

## Tech stack

| Concern | Choice |
|---|---|
| GUI | `egui` / `eframe` (wgpu or glow backend) |
| Terminal emulation | `alacritty_terminal` (state machine + grid), rendered by our own egui widget |
| Local shell | `portable-pty` (Unix PTY / Windows ConPTY) |
| SSH, SFTP, tunnels | `russh`, `russh-sftp` (pure Rust, tokio) |
| Async runtime | `tokio` |
| Config | `serde` + TOML, stored under the platform config dir (`directories`) |
| Secrets | `keyring` (Secret Service / Windows Credential Manager / macOS Keychain) |
| Quick servers | `axum` + `tower-http` (HTTP), `async-tftp`, `libunftp` (FTP), `russh` server (SSH/SFTP) |
| Serial | `serialport` |
| RDP / VNC (later) | `ironrdp`, a VNC client crate |

Not planned: a built-in X server. Linux/macOS already have one; on Windows the
user can run an external X server for X11 forwarding.

## Architecture

```
crates/
  wazowski-app/       # binary: window, tabs, sidebars, menus, settings UI
  wazowski-term/      # terminal widget: alacritty_terminal + egui rendering + input
  wazowski-core/      # session models, config, keychain, shared types
  wazowski-ssh/       # SSH, SFTP, port forwarding
  wazowski-servers/   # quick servers
```

The terminal widget is backend-agnostic: anything that can send and receive
bytes and accept a resize (local PTY, SSH channel, serial port, Telnet socket)
implements a `Backend` trait and is plugged into a `Terminal`.

## Phases

1. **Foundation** ✅ — workspace, window, tabs, local shell in a working terminal
   (colors, cursor, scrollback, keyboard input, copy/paste, resize).
2. **SSH** ✅ — password/key/agent auth, host key verification (known_hosts),
   saved sessions in a session-manager sidebar. Secrets live in an encrypted
   vault (Argon2id + XChaCha20-Poly1305), optionally unlocked via the OS
   keyring. Credentials are referenced by name so keys can be shared.
3. **SFTP sidebar** ✅ — file browser beside the active SSH tab (shares the SSH
   connection), navigate directories, upload/download via native dialogs,
   new folder, delete. Operations run off the UI thread. (Drag-and-drop and
   following the terminal's working directory: future polish.)
4. **Quick servers** ✅ — a Servers tab to start/stop HTTP, TFTP, SFTP, and
   iperf3 servers on a chosen folder, interface and port, with live logs.
   Configs persist; bind address is selectable. (iperf drives the system
   `iperf3` binary.)
5. **Power features** ✅ — serial connections, multi-exec broadcast (with
   per-terminal exclude), recursively splittable panes, configurable
   keybindings, and user macros (text / key / expect / delay steps).
   (SSH tunnels/port-forwarding deferred to a later "hopeful future" phase.)
   Broadcast is strictly scoped to the **active tab**: typed/pasted/macro input
   never reaches a tab the user can't see. The toolbar order is Split right |
   Split down | Broadcast, and Broadcast is greyed (with an explanatory tooltip)
   until the tab has more than one pane. Scope is enforced in input dispatch, not
   just the button, so a stored flag or the keyboard shortcut can't leak input.
6. **UX & management** ✅ — settings tab, single-instance, startup/new-tab/vault
   backup options, About, edit-shared-sources, left-pane Sessions/Macros switcher,
   delayed hover tooltips, find-in-terminals, keep-ended-tabs-open, recent-sessions
   launcher, versioned release filenames, and session-aware split panes.
7. **Extras and packaging** — RDP/VNC, RPM + Flatpak, Windows installer, macOS app bundle.
   (First step done: `packaging/linux/` ships a `wazowski.desktop` launcher +
   `install-linux.sh` that installs the hicolor icons, so Linux app menus/docks show
   the real icon. `StartupWMClass` matches the `with_app_id("wazowski")` window id.
   Full RPM/Flatpak/installer/bundle work is still future.)

Each phase ends with something runnable.

## Phase 6 backlog — UX & management (requested 2026-10-14)

Agreed "do next" items (rough order TBD with the user):

- **Release filenames carry the version** ✅ (tag is embedded in each asset name).
- **Session-aware split panes** ✅ — each split pane has a title-bar menu to show
  New shell / another single-terminal tab's session / return-to-its-tab. Picking
  a session moves it into the pane; its origin tab shows a placeholder with a
  bring-back button, and it returns to its original tab position on close.
  (Known limitation: a moved SSH session loses its SFTP panel.)
- **Left-pane view switcher** ✅ — Sessions/Macros tabs at the top of the left
  pane; Macros view: double-click runs (confirm dialog), right-click for run
  targets / edit / duplicate / delete; Ctrl+Shift+M switches to it.
- **Settings tab** ✅ — Terminal ▸ Settings, rendered like a session tab,
  persisted to settings.toml:
  - Automatic vault backup (enable, interval, folder, open-folder, back-up-now). ✅
  - Single-instance enforcement (advisory lock, fs2) unless allowed. ✅
  - Startup tab (nothing / local shell / a saved session). ✅
  - New-tab placement: Never / When duplicating / Always. ✅
- **Edit shared sources** ✅ — right-click ▸ Edit source…; folder path, or git
  url/branch/file/auth, all editable in place.
- **Hover tooltips in the left pane** ✅ — ~3 s delayed; sessions show
  address/auth/legacy, shared sources show folder/git details.
- **Find in terminals** ✅ — Ctrl+Shift+F; highlights matches on the visible
  panes with a live count; case-insensitive by default + a case toggle.
- **Keep closed SSH tabs open** ✅ — ended SSH/serial tabs stay with Restart /
  Save output… / Close; local shells auto-close.
- **Recent-sessions launcher** ✅ — the empty "Wazowski" screen lists the last 10
  sessions to resume.
- **About view** ✅ — Terminal ▸ About Wazowski: version + repo/releases links.

## Phase 7 — network toolbox ✅

- **Port scanner** ✅ — common ports or a user range/list.
- **Subnet scanner** ✅ — ping sweep + per-host common-service detection and a
  port-scan button.
- **List open ports on the host** ✅ (via `ss`/`netstat`).
- **Wake-on-LAN** ✅ — magic packet to broadcast.

## Shell overhaul (done)

- **Custom title bar** — native window decorations are off; a custom bar draws the
  app-icon menu (About / Quit), title, theme toggle, and minimize/maximize/close.
  Dragging the bar moves the window; double-click maximizes. (Edge-resize may be
  limited under some Linux compositors — a follow-up could add resize handles.)
- **Left-rail views** — the top menu bar is gone. The rail now has Sessions,
  Macros, Files, **Tools**, **Vault**, Settings.
- **Tools pane** — categories Servers (HTTP/TFTP/SFTP/iperf3), Network Tools
  (IP Scanner / Port Scan / Wake-on-LAN), Host Tools (Open Ports). Each server is
  one-per-protocol: a config row (folder, interface, port, SFTP creds, stop-after
  timer checkbox) with the live console filling the rest; Start/Stop inline (no
  start-time prompt). Network/host tools render in the same area.
- **Vault pane** — credentials listed by type (passwords / private keys); click to
  edit or delete; "Show password/key" reveals the value after master-password
  re-auth. Vault file operations (create/unlock/import/back up/delete, plus the
  advanced secrets manager with key generation) moved to Settings ▸ Vault.
- **Keybindings** moved into Settings ▸ Keybindings.

## Later backlog (roadmap, not yet scheduled)

- **SFTP: follow the terminal's working directory** — when the shell changes
  directory, move the SFTP pane to match. (Removed from beta for now; needs a
  reliable cwd source — OSC 7 is tracked in `Terminal::cwd`, but the title-based
  path and some shells don't report it.)
- **Web bookmark "sessions"** — save a web URL as a session entry so a device's
  GUI web page can be opened quickly (e.g. in the browser) from the session tree.
  (Partial: a session's right-click ▸ "Open web GUI" opens its host in the
  default browser, using the http/https scheme set in Settings ▸ General. A
  standalone web-only bookmark entry is still future work.)
- **Terminal color customization** — editable palette (background, foreground,
  cursor, 16 ANSI colors) and/or preset themes. (Font size and regex highlights
  are done; this is the remaining part of "terminal customization".)
- **File diff comparison.**
- **List host hardware.**
- **Running processes view** — likely `htop` in a tab, or a native list.
- **Auto-updater** — best-practice update flow with a "Check for updates" button.
- **Settings categories** — left-side category buttons (General / Tabs / Vault /
  Terminal / Extras). General: single-instance + "open a local shell on startup"
  checkbox. Tabs: new-tab placement as a dropdown. Extras: environment checks with
  fix buttons (low-port permission/setcap, iperf3 install, printing service,
  detected RDP client, default web browser). ✅ (done; General also has the
  "Open web GUI with: http/https" scheme setting.)
- **Per-session network tools** ✅ — right-click a session → Network tools
  (Ping, Port scan common, Port scan 1-1024, Scan subnet /24) targeting its
  host; opens the Network toolbox prefilled and runs the chosen tool. (The
  toolbox also gained a single-host Ping button alongside the port scanner.)
- **OpenVPN quick server** — add an OpenVPN server to Quick servers, ideally with
  NAT punch-through / UPnP / proxy to spin up a reachable VPN quickly.
- **App VPN routing** — route only Wazowski's traffic through a chosen VPN, with an
  optional "force" toggle: while forcing + connecting, open the VPN settings with a
  loading indicator and block other use until connected or the toggle is cleared;
  on failure, require fixing it or clearing force.
- **Wireshark quick launch** — a Network-tools button to start a Wireshark capture.
- **RDP & VNC via external clients** ✅ — RDP and VNC are first-class saved
  session types (the session editor has a type-picker row of icon buttons:
  SSH / RDP / VNC). Connecting an RDP/VNC session launches the user's installed
  client (FreeRDP / Remmina / Windows mstsc for RDP; vncviewer / TigerVNC /
  Remmina / macOS Screen Sharing for VNC) with host:port, plus username/domain
  for RDP. Preferred clients are configurable in Settings ▸ Extras (Auto or a
  specific one), which also reports whether each is installed. RDP/VNC can
  reference a vault Password credential; the password is handed to the client
  over stdin (FreeRDP `/from-stdin`, TigerVNC `-autopass`) so it never appears
  in the process list (other clients prompt). RDP also supports "Connect as…"
  for one-off credentials. Session types have distinct default colors
  (SSH default/white, RDP blue, VNC orange).
  (Follow-up: RDP resolution/gateway options, VNC quality options.)
- **Appearance picker** ✅ — the icon/color control (sessions, folders, shared
  sources, and now macros) is a single button showing the current icon tinted
  with its color; clicking opens a picker with an inline color selector above a
  live-recoloring icon grid plus a custom-glyph field. Macros carry their own
  icon/color (default gear + theme color). Used on session, folder (create + edit),
  shared-source and macro dialogs. The picker is a `Popup` with CloseOnClickOutside
  (not a menu button, which closed on any inner click — so the color sliders and
  custom-emoji field now stay open). (Follow-up: custom *image-file* icons —
  deferred because icons render inline in `RichText` at every tree/tab row, so
  image support means reworking each render site.)
- **In-window RDP/VNC + tab detach** — embed RDP/VNC in a tab via native Rust
  clients rendering into an egui texture like the terminal widget. (Decided
  2026-10-18; embedding external client windows was rejected as
  X11-only/Wayland-breaking.)
  - **VNC** ✅ — native in-window via `vnc-rs` in the new `wazowski-remote` crate.
    The backend runs on its own thread/Tokio runtime, publishes an RGBA
    framebuffer and takes mouse/keyboard input through `RemoteHandle`; the
    `remote_view` widget blits it into a letterboxed texture and maps input to
    X11 keysyms. Options: view-only and encoding quality (Auto/High/Low). Opens
    as `TabContent::Remote`; vault/connect creds as before. Tab toolbar ops:
    Screenshot (save a PNG of the session) and Paste text (type this machine's
    clipboard into the session, confirming on multi-line).
    Security types: None, VNC Authentication, and **VeNCrypt with an X509
    sub-type** (261 X509Vnc / 260 X509None) — we run the RFB handshake ourselves
    (in `wazowski-remote::vnc::connect`) and hand the authenticated stream to a
    vendored `vnc-rs` (`vendor/vnc-rs`, with `VncClient::new`/`AuthHelper` exposed).
    TLS uses rustls+ring with certificate verification disabled (self-signed is
    normal for these devices). This was added for a Toshiba copier that offers
    VeNCrypt (works in Remmina). (Still unsupported: VeNCrypt *anonymous*-TLS
    sub-types — 258 TLSVnc / 18 TLS — because rustls can't do anon-DH; and
    Tight/RA2/Apple. A copier only offering anon-TLS, or TLS < 1.2, would still
    fail — fall back to an external viewer there.)
  - **RDP** ✅ — native in-window via `ironrdp` (connect → TLS rustls+ring →
    CredSSP/NLA → `ActiveStage`; decoded RGBA published to the framebuffer; mouse
    + keyboard via fast-path, text sent as Unicode and Ctrl/Alt combos + specials
    as scancodes). Options: resolution (blank = fit) and vault/connect creds.
    Tab toolbar ops: Screenshot, Paste text (clipboard → keystrokes, confirm on
    multi-line), Ctrl+Alt+Del, and Windows (Super) key.
    The ironrdp↔russh `curve25519`/`ecdsa` pre-release conflict was resolved by
    vendoring **`picky`** and **`sspi`** (`vendor/`, via `[patch.crates-io]`) with
    their exact pre-release crypto pins relaxed to caret, so everything resolves to
    the stable RustCrypto releases (the rc→final APIs were compatible). The old
    external-client launch was removed. (Follow-up: Deactivate-All / dynamic
    resize handling currently ends the session rather than reactivating.)
  - **Tab detach** — pop a tab into its own egui viewport. Not started.
- **Broadcast safety** ✅ — switching tabs disarms broadcast; the per-pane
  exclude toggle only shows when the tab has split panes.
- **Context-menu convention** ✅ — every right-click menu puts generic actions
  (copy/delete/duplicate/edit/move) in a lower section under a separator, in
  alphanumeric order; context-specific actions stay on top. Applies to new menus.
- **Visual polish / "make the UI cooler"** — themes, fonts, animations; done last.

## Portability goals

- **ARM / Raspberry Pi** — build and run on arm64 (and smaller SBCs if feasible).
- **Android (and maybe iOS)** — at least carry sessions and connect from a phone;
  stripping features is acceptable. iOS is low priority.
- **Web app via Docker** — run Wazowski as a browser-accessible web app served
  from a Docker container (e.g. egui/eframe compiled to WASM, or a thin web
  front-end), so it can be hosted and used without a local install.
