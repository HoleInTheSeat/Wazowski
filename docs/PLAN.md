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
6. **UX & management** (next) — see the backlog below.
7. **Extras and packaging** — RDP/VNC, RPM + Flatpak, Windows installer, macOS app bundle.

Each phase ends with something runnable.

## Phase 6 backlog — UX & management (requested 2026-10-14)

Agreed "do next" items (rough order TBD with the user):

- **Release filenames carry the version** ✅ (tag is embedded in each asset name).
- **Session-aware split panes** — splitting a pane shows a MobaXterm-style title
  bar per split area; clicking it picks which currently-open tab/session that
  split displays (panes reference sessions rather than owning a single shell).
- **Left-pane view switcher** — tabs at the top of the left pane to toggle
  between Sessions and Macros. The Macros view lists macros: double-click runs
  (with the confirm dialog), right-click for edit/delete/duplicate/run-targets.
- **Settings tab** — opened from the Terminal menu, rendered like a session tab;
  holds global options, persisted. Settings to include:
  - Automatic vault backup options.
  - Single-instance enforcement (block a second Wazowski unless allowed here).
  - Startup tab (a chosen session, or none).
  - New-tab placement: Never (append at far right) / When duplicating / Always
    (open next to the current tab).
- **Edit shared sources** — edit a folder share's path, and a git share's url,
  branch, file, and auth (for renames, moved repos/branches, changed auth).
- **Hover tooltips in the left pane** — after ~3 s, brief useful info (e.g. a git
  share shows it's a repo plus the repo name), kept concise.
- **Find in terminals** — Ctrl+Shift+F searches on-screen terminals for entered
  text; case-insensitive with substring match by default, with options.
- **Keep closed SSH tabs open** — when a session ends, keep the tab with buttons
  to restart the session, save the terminal buffer to a file, or close.
- **Recent-sessions launcher** — the empty "Wazowski" screen shows a grid/list of
  buttons for the last 10 sessions to quickly resume.
- **About view** — version, and links to GitHub/changelog/etc.; opened from the
  Terminal menu.

## Later backlog (roadmap, not yet scheduled)

- **Port scanner** — scan an IP for "common" ports or a user range/list.
- **Subnet scanner** — ping each IP, then a button per host to port-scan it;
  auto-scan common service ports (ssh/rdp/vnc/ftp/http/…) like MobaXterm.
- **List open ports on the host** running Wazowski.
- **File diff comparison.**
- **List host hardware.**
- **Running processes view** — likely `htop` in a tab, or a native list.
- **Auto-updater** — best-practice update flow with a "Check for updates" button.
- **Icons & colors for shared sessions / folders** — e.g. a switch clip-art icon
  and custom color for a folder of switch sessions.
- **Wake-on-LAN** — send magic packets.
- **Visual polish / "make the UI cooler"** — themes, fonts, animations; done last.

## Portability goals

- **ARM / Raspberry Pi** — build and run on arm64 (and smaller SBCs if feasible).
- **Android (and maybe iOS)** — at least carry sessions and connect from a phone;
  stripping features is acceptable. iOS is low priority.
