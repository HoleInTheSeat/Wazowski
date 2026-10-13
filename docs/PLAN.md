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

1. **Foundation** — workspace, window, tabs, local shell in a working terminal
   (colors, cursor, scrollback, keyboard input, copy/paste, resize).
2. **SSH** — password/key/agent auth, host key verification (known_hosts),
   saved sessions in a session-manager sidebar, credentials in the keychain.
3. **SFTP sidebar** — browse the remote filesystem of the active SSH tab,
   upload/download, drag and drop, follow the terminal's working directory.
4. **Quick servers** — panel to start/stop HTTP, TFTP, FTP, SFTP servers on a
   chosen folder and port, with live logs.
5. **Power features** — SSH tunnels, split panes, multi-exec, serial, Telnet,
   themes, fonts, keybinding settings.
6. **Extras and packaging** — RDP/VNC, RPM + Flatpak, Windows installer, macOS app bundle.

Each phase ends with something runnable.
