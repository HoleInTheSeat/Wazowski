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
6. **UX & management** ✅ — settings tab, single-instance, startup/new-tab/vault
   backup options, About, edit-shared-sources, left-pane Sessions/Macros switcher,
   delayed hover tooltips, find-in-terminals, keep-ended-tabs-open, recent-sessions
   launcher, versioned release filenames, and session-aware split panes.
7. **Extras and packaging** — RDP/VNC, RPM + Flatpak, Windows installer, macOS app bundle.

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

## Later backlog (roadmap, not yet scheduled)

- **File diff comparison.**
- **List host hardware.**
- **Running processes view** — likely `htop` in a tab, or a native list.
- **Auto-updater** — best-practice update flow with a "Check for updates" button.
- **Icons & colors for shared sessions / folders** — e.g. a switch clip-art icon
  and custom color for a folder of switch sessions.
- **Visual polish / "make the UI cooler"** — themes, fonts, animations; done last.

## Portability goals

- **ARM / Raspberry Pi** — build and run on arm64 (and smaller SBCs if feasible).
- **Android (and maybe iOS)** — at least carry sessions and connect from a phone;
  stripping features is acceptable. iOS is low priority.
- **Web app via Docker** — run Wazowski as a browser-accessible web app served
  from a Docker container (e.g. egui/eframe compiled to WASM, or a thin web
  front-end), so it can be hosted and used without a local install.
