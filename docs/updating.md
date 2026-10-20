# Updating Wazowski

Wazowski can update itself from its GitHub Releases.

## Checking for updates

- Open the **app menu** (the Wazowski icon at the top-left) → **Check for
  updates…**. Wazowski also checks quietly on startup; when a newer version is
  out, the menu shows **⬆ Update to vX.Y.Z…**.
- The update dialog shows the new version and its release notes.

## Installing an update

How the update is applied depends on how you installed Wazowski:

| Install | Auto-update |
|---|---|
| **Windows installer** (per-user) | **Yes** — downloads and replaces the app, no admin prompt. Click **Restart now** when it's done. |
| **Linux AppImage** | **Yes** — replaces the `.AppImage` in place. |
| **Raw binary** (downloaded exe/binary) | **Yes**, if the file is writable. |
| **Linux RPM (`dnf`)** | **No** — it's owned by your package manager. The dialog tells you to run `dnf upgrade` instead. |
| **macOS** | **Yes** — replaces the app (you may get an "unidentified developer" prompt, since builds are unsigned). |

After **Download & install**, choose **Restart now** to relaunch into the new
version (or **Later** to restart yourself).

## Windows installer

The Windows release includes **`wazowski-<version>-windows-x86_64-setup.exe`** — a
per-user installer that adds a Start Menu (and optional desktop) shortcut and an
uninstaller, and installs to `%LOCALAPPDATA%\Programs\Wazowski` so updates need no
admin rights. The plain `…-windows-x86_64.exe` is still provided as a portable
build.

> Builds are **unsigned**, so Windows SmartScreen may warn ("Windows protected
> your PC") on first run of the installer and of each update — choose **More
> info → Run anyway**. Defender may also occasionally flag an unsigned update.
