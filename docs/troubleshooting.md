# Troubleshooting

## Linux: launcher/taskbar icon doesn't appear after installing the RPM

The package installs the icons and desktop entry correctly, but some desktops
cache icons per-user and don't refresh until prompted. On **KDE Plasma**:

```sh
kbuildsycoca6 --noincremental
rm -f ~/.cache/icon-cache.kcache
# then reload the shell:
kquitapp6 plasmashell && kstart plasmashell    # or just log out and back in
```

On Wayland the taskbar icon comes from matching the running window's app id to the
`wazowski.desktop` entry, so after refreshing the cache you may also need to
**relaunch Wazowski** once for its window to pick up the icon. A fresh login on a
new machine won't hit this.

## Linux: "Discover" (or another GUI store) hangs installing the `.rpm`

GUI app stores are poor at installing **local, unsigned** RPM files and may spin
on "loading". Install from the terminal instead:

```sh
sudo dnf install ./wazowski-*-linux-x86_64.rpm
```

## A shared source shows "(offline)"

The share or git remote wasn't reachable at the last sync. Wazowski keeps using
the **local cache** (read-only). Fix connectivity/auth and **Sync now**
(right-click the source). For a folder source whose file was deleted, the
offline prompt can **recreate** it from the cache. See
[Shared sessions](shared-sessions.md).

## Unpushed shared-session changes

Git shares commit locally and don't push automatically. Use **Sync now** (it
confirms before pushing) or push/discard from the **quit** prompt. A failed push
keeps your local commits — they're offered again next launch. Details in
[Shared sessions](shared-sessions.md).

## SSH won't connect to old equipment

Turn on **legacy mode** for that session to allow SHA-1 key exchange, CBC
ciphers, and DSA/`ssh-rsa` host keys (ProCurve/HPE and similar). The handshake
log on the connection tab shows exactly where negotiation failed.

## "Host key changed" warning

The server's key differs from the one recorded in `~/.ssh/known_hosts`. This can
mean the host was reinstalled — or a man-in-the-middle. Only trust the new key if
you expected the change.

## RDP feels sluggish

- Lower the session's **Quality** to *Balanced* or *Performance*
  ([Connections](connections.md)).
- A **release** build is far faster than `cargo run` (debug) for codec decoding —
  use a packaged build or `cargo run --release`.

## Clipboard paste into RDP/VNC

Use the session toolbar's **Paste text** button, which types your clipboard as
keystrokes. Multi-line pastes ask for confirmation first, since newlines act as
Enter.

## Optional tools missing

**Settings → Extras** shows which optional helpers are present (`jq`, `smbclient`,
`iperf3`, printing, RDP/VNC clients) and can install or grant permissions where
possible.
