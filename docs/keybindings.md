# Keyboard shortcuts

All shortcuts are listed and **rebindable** in **Settings → Keybindings**. The
defaults are below.

| Action | Default |
|---|---|
| New local shell | `Ctrl+Shift+T` |
| Close tab | `Ctrl+Shift+W` |
| Next tab | `Ctrl+PageDown` |
| Previous tab | `Ctrl+PageUp` |
| Split pane right | `Ctrl+Shift+E` |
| Split pane down | `Ctrl+Shift+O` |
| Close focused pane | `Ctrl+Shift+X` |
| Toggle broadcast | `Ctrl+Shift+B` |
| Save output / screenshot | `Ctrl+S` |
| Find in terminals | `Ctrl+Shift+F` |
| Serial: raise baud | `Ctrl+Shift+↑` |
| Serial: lower baud | `Ctrl+Shift+↓` |
| Sessions pane | `Ctrl+Shift+1` |
| Files pane | `Ctrl+Shift+2` |
| Macros pane | `Ctrl+Shift+3` |
| Tools pane | `Ctrl+Shift+4` |
| Vault pane | `Ctrl+Shift+5` |
| Settings pane | `Ctrl+Shift+S` |
| Terminal: larger font | `Ctrl+=` |
| Terminal: smaller font | `Ctrl+-` |
| Terminal: reset font size | `Ctrl+0` |

Each pane shortcut switches to that pane **and** moves the keyboard there — into
the sessions tree (for arrow-key navigation) for the Sessions pane, or into the
pane's filter box for the others.

**Save output / screenshot** (`Ctrl+S`) acts on the active tab: a terminal tab's
scrollback is saved to a text file, and an RDP/VNC tab's current frame is saved
as a PNG — both ask where to save. Note this overrides the terminal's `Ctrl+S`
flow-control (XOFF); rebind it if you need XOFF.

## Rebinding

In **Settings → Keybindings**, click a shortcut and press the new combination to
rebind it. Use the filter box at the top to find an action quickly. Changes are
saved to `keybindings.toml` in your config dir and are included in a
[settings backup](settings-and-backup.md).

## Macro shortcuts

A macro can have its own shortcut (set in the macro editor). It runs the macro on
the active terminal, and only fires while a terminal tab has keyboard focus — so
it never clashes with typing in the sidebar, a filter box, or a dialog. See
[Macros](macros.md).

## Font zoom with the mouse

In addition to the keys above, `Ctrl+scroll` over a terminal changes its font
size.
