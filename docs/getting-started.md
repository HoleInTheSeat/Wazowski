# Getting started

## Install

Download a build from the
[Releases](https://github.com/HoleInTheSeat/Wazowski/releases) page.

### Linux

Two packaged formats are published alongside the raw binary:

- **Fedora RPM** — installs the binary, a desktop entry, and icons:

  ```sh
  sudo dnf install ./wazowski-*-linux-x86_64.rpm
  ```

- **AppImage** — portable, runs on most distributions with no install:

  ```sh
  chmod +x Wazowski-*-x86_64.AppImage
  ./Wazowski-*-x86_64.AppImage
  ```

If you run the **raw binary** instead, install the GUI runtime libraries listed
in the [README](../README.md#install).

Optional command-line helpers Wazowski uses when they're present:

| Tool | Enables |
|---|---|
| `jq` | Filtering in the JSON/jq puller |
| `smbclient` (Samba client) | Browsing an RDP host's files over SMB |
| `iperf3` | The iperf3 quick server |
| `lp` / `lpr` (CUPS) | "Print output" from a tab |
| `git` | Git-backed shared sessions |

The RPM lists these as weak dependencies (recommended, not required).

### Windows and macOS

Download the matching binary from Releases and run it. Native RDP/VNC, SSH, and
serial work cross-platform. (The SMB file browser currently relies on
`smbclient`, so it is Linux-only for now.)

## First launch

On first run you get an empty window. A few things to do:

1. **Create a vault** (optional but recommended) so you can save passwords and
   keys. Left pane → **Vault** → unlock/create. See [Vault](vault.md).
2. **Add a session.** Left pane → **Sessions** → the **+** button, or right-click
   the empty pane → **New session**. See [Session manager](session-manager.md).
3. **Connect.** Double-click a session, or type `user@host` into the **Quick**
   box and press Enter.

![Wazowski main window](images/main-window.png)

## A tour of the window

- **Title bar** — custom window controls plus the app menu (`⬢`).
- **Left pane icon rail** — switches the left pane between six views:
  - 🖥 **Sessions** — your saved connections, in folders, plus the serial dock.
  - 📜 **Macros** — saved keystroke/command macros.
  - 📁 **Files** — the SFTP browser (SSH tabs) or SMB browser (RDP tabs).
  - 🔧 **Tools** — quick servers and network/host tools.
  - 🔒 **Vault** — saved credentials.
  - ⚙ **Settings** — all preferences, keybindings, and backup.
- **Tab strip** — one tab per connection or shell; **+** opens a local shell.
- **Main area** — the active tab's terminal or remote session; a tab can be
  split into panes.

Continue with [Terminal, tabs & panes](terminal.md) or jump to
[Connections](connections.md).
