# Wazowski documentation

Wazowski is a MobaXterm-style terminal, remote-session, and network toolbox. One
tabbed window holds your local shells, SSH/SFTP, in-window RDP and VNC, serial
consoles, saved sessions, credentials, macros, quick servers, and network tools.

## Contents

1. [Getting started](getting-started.md) — install, first launch, and a tour of
   the window.
2. [Terminal, tabs & panes](terminal.md) — the emulator, tabs, split panes,
   broadcast, find, fonts, and saving/printing output.
3. [Connections](connections.md) — SSH, SFTP, RDP, VNC, and serial, plus the
   remote-ops toolbar and SMB file browsing.
4. [Session manager](session-manager.md) — folders, drag-and-drop, icons and
   colors, right-click actions, and quick connect.
5. [Vault (credentials)](vault.md) — the encrypted store, auth methods, key
   generation, and backups.
6. [Shared sessions](shared-sessions.md) — sharing sessions via a folder or a git
   repo, syncing and pushing changes, and descriptions.
7. [Macros](macros.md) — recording and replaying keystrokes across terminals.
8. [Quick servers](quick-servers.md) — HTTP / TFTP / SFTP / iperf3 servers.
9. [Network & host tools](tools.md) — the JSON/jq puller, API client, IP-address
   viewer, and per-session network tools.
10. [Settings & backup](settings-and-backup.md) — every setting, plus exporting
    and importing your whole configuration.
11. [Keyboard shortcuts](keybindings.md) — the default keymap and how to rebind.
12. [Importing from MobaXterm](importing-from-mobaxterm.md) — converting
    `.mxtsessions` files.
13. [Updating](updating.md) — in-app updates and the Windows installer.
14. [Troubleshooting](troubleshooting.md) — common issues and fixes.

## Core concepts

- **Tabs** hold connections and shells; a tab can be **split** into panes.
- The **left pane** switches between six views via the icon rail: **Sessions**,
  **Macros**, **Files**, **Tools**, **Vault**, and **Settings**.
- **Sessions** are saved connection definitions (SSH/RDP/VNC) organised in
  folders. They hold no secrets — credentials are referenced by name from the
  **vault**.
- **Shared sessions** come from a shared folder or git repo and are cached
  locally so they work offline.

> Screenshots in these pages live in [`images/`](images/). If one is missing,
> the page still reads fine — the text stands on its own.
