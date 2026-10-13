# Wazowski

A MobaXterm-style terminal and remote-session toolbox, written entirely in Rust.
Primary target is Fedora Linux; it also builds for Windows and macOS.

> **Status: first beta (v0.1.0-beta.1).** The core workflow is usable day to day;
> expect rough edges and occasional breaking changes.

## Features

- **Tabbed terminal** with a full emulator (colors, scrollback, selection,
  copy-on-select, right-click paste) running your local shell.
- **SSH sessions** as tabs, with password, private-key, and SSH-agent auth, and
  host-key verification against `~/.ssh/known_hosts`. A per-session **legacy
  mode** enables old algorithms (SHA-1 KEX, CBC ciphers, DSA/ssh-rsa host keys)
  for gear like HPE/ProCurve switches. Connections show a live, copyable
  handshake log with retry.
- **SFTP file browser** beside the active SSH tab (same connection): browse,
  upload, download, new folder, delete.
- **Encrypted vault** for passwords and private keys (Argon2id +
  XChaCha20-Poly1305), optionally unlocked automatically via the OS keyring.
  Credentials are named and can be shared across sessions; you can also
  generate Ed25519 key pairs.
- **Session manager** with nested folders, right-click menus, drag-and-drop, and
  move/copy of sessions and whole folders.
- **Session sharing** via a shared file/folder (network mount, NAS, synced
  folder) or a **git repo** (GitHub, GitLab, Forgejo, …) with optional
  per-repo auth (HTTPS token in the OS keyring, or an SSH key). Shared sessions
  are cached locally so they survive the share being offline, and never store
  secrets — credentials are created locally on first use.

## Install

Download a binary for your platform from the
[Releases](https://github.com/HoleInTheSeat/Wazowski/releases) page.

On **Linux** the GUI needs these runtime libraries (install via your package
manager if they aren't already present):

- Fedora: `sudo dnf install libxkbcommon wayland-libs libX11 libXcursor libXrandr libXi mesa-libGL`
- Debian/Ubuntu: `sudo apt install libxkbcommon0 libwayland-client0 libx11-6 libxcursor1 libxrandr2 libxi6 libgl1`

The SFTP/file dialogs use `xdg-desktop-portal`; git sharing uses the system
`git` binary.

## Build from source

Requires the Rust toolchain ([rustup](https://rustup.rs)) and a C toolchain.

```sh
# Fedora build dependencies
sudo dnf install gcc gcc-c++ make libxkbcommon-devel wayland-devel \
  libX11-devel libXcursor-devel libXrandr-devel libXi-devel mesa-libGL-devel

git clone https://github.com/HoleInTheSeat/Wazowski.git
cd Wazowski
cargo run --release
```

## Project layout

```
crates/
  wazowski-app/     GUI: tabs, session manager, vault/sharing, dialogs
  wazowski-term/    terminal widget (alacritty_terminal + egui)
  wazowski-core/    encrypted vault, sessions, folders
  wazowski-ssh/     SSH/SFTP backends, host-key checks, key generation
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
