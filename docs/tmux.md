# tmux sessions

The **tmux** pane lists and manages [tmux](https://github.com/tmux/tmux)
sessions — both on this machine and on the host of the SSH tab you're currently
looking at — so you can attach, create, rename, and terminate them without
remembering tmux's command-line incantations.

Open it from the icon rail (the grid icon, under Files) or with
**`Ctrl+Shift+3`**.

tmux is a *terminal multiplexer*: it keeps shells and running programs alive in
named **sessions** that survive you disconnecting, so you can detach and
reattach later and find everything as you left it. Wazowski doesn't bundle tmux
— it drives the `tmux` already installed on the machine (local) or on the remote
host (over the SSH connection).

## Two folders: Local and Remote

- **Local** — tmux sessions on the computer running Wazowski. Shown whenever
  `tmux` is on your `PATH`; if it isn't, the folder says so.
- **Remote** — tmux sessions on the host of the **currently active SSH tab**.
  Switch to a different SSH tab and the folder follows it; with no SSH tab
  active it prompts you to open one. The host is named under the heading — its
  friendly name (the saved session's name / hostname), or the address you
  connected to if there's no friendlier name. **Click that name** to detach and
  drop back to the plain SSH shell in that tab. Detaching sends the tmux
  **prefix + `d`** keystroke (the prefix is read from the host, so a remapped
  prefix such as `Ctrl+a` still works), which detaches **only your client** —
  anyone else attached to the same session stays connected. If the shell isn't
  in a tmux session to begin with, clicking the name just brings that tab to the
  front (there's nothing to detach, so no keystroke is sent).

Each session row shows its name, its window count, and a dot (`●`) when a client
is already attached. The list refreshes automatically every couple of seconds
while the pane is open, and there's a refresh button (↻) in the header. Use the
filter box to narrow a long list by name.

## Attaching

**Click a session** (or right-click → **Attach**) to attach to it:

- **Local** opens a new terminal tab running `tmux attach` for that session.
  Detaching (tmux's `Ctrl+b d`) or ending the session exits the tab, and the
  session keeps running. If that session is **already open in a tab**, clicking
  it just switches to that tab instead of opening a second one.
- **Remote** types `tmux attach` into the active SSH tab's shell — the normal
  way to attach over an existing connection. Make sure that shell is at a prompt
  first. If the shell is already showing a *different* tmux session, clicking
  another one first **detaches** your client from the current session (the same
  prefix + `d` keystroke as above, so only your client drops and no one else is
  disturbed) and then attaches to the new one — you never see tmux's "sessions
  should be nested" warning, and because the detach is a keystroke it works even
  when a pane is running a full-screen program. The attach command is only typed
  **once the shell is confirmed back from tmux** (Wazowski watches for the tab to
  leave tmux's full-screen display), so it can never be typed into a session you
  were only observing. If that can't be confirmed within a few seconds, nothing
  is typed and you're told to run `tmux attach` yourself.

Either way, clicking the session you're **already in** does nothing.

## Split and broadcast drive tmux while you're attached

While a tab is attached to a tmux session, the tab toolbar's **split** buttons
(and their keybinds) split the **tmux** window instead of Wazowski's own panes:
**⇥** splits left/right, **⇩** splits top/bottom. The **Broadcast** (⇉) button
toggles tmux's **`synchronize-panes`**, which mirrors what you type to every pane
in the window — the tmux equivalent of broadcast. The button lights up while
synchronize-panes is on.

These run as tmux commands over the side channel (the SSH connection for a remote
session, a local command for a local one), targeting the session by name — so
nothing is typed into the panes you're watching, and every attached client sees
the change live. As soon as you detach (back to the shell), the same buttons go
back to splitting and broadcasting Wazowski's own panes.

## Creating, renaming, terminating

Right-click a session for the full menu, or use **＋ New session…** at the
bottom of either folder:

- **New session…** — prompts for a name and creates a detached session
  (`tmux new-session -d`). By default it then **switches you to the new session**
  (attaching, detaching any current one first just like clicking it would);
  untick **Switch to it after creating** to leave it detached in the list
  instead.
- **Rename…** — prompts for a new name.
- **Terminate** — kills the session after a confirmation. Everything running in
  it is stopped and any attached clients are detached. **This can't be undone** —
  it's different from *detaching*, which leaves the session running.

Remote actions run over the SSH connection in the background, so the UI never
blocks waiting on the network; any error is surfaced afterward.

## Requirements

- **Local:** `tmux` installed and on your `PATH`.
- **Remote:** an active SSH tab, with `tmux` installed on that host. Listing uses
  a one-off command over the same SSH connection (no extra login).

## tmux's own shortcuts

Once you're attached, you're in tmux, which has its own keys (prefixed by
`Ctrl+b`). **Settings → Keybindings** includes a read-only **tmux shortcuts**
reference for the common ones. Those are tmux defaults configured in
`~/.tmux.conf`, not in Wazowski. See [Keyboard shortcuts](keybindings.md).
