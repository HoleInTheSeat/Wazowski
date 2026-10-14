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
5. **Power features** — SSH tunnels, split panes, multi-exec, serial, Telnet,
   themes, fonts, keybinding settings.
6. **Extras and packaging** — RDP/VNC, RPM + Flatpak, Windows installer, macOS app bundle.

Each phase ends with something runnable.
