# Importing from MobaXterm

If you're coming from MobaXterm, the `tools/mxt2wazowski.py` script converts a
MobaXterm sessions export (`.mxtsessions`) into a Wazowski **session tree** (a
directory of `.folder` and `.wzsession` files) you can share with a team.

## Requirements

- Python 3.11+ (uses the standard library only — `tomllib`).

## Usage

```sh
# One file → a "team/" directory next to it (the tree root)
python3 tools/mxt2wazowski.py team.mxtsessions

# Choose the output directory
python3 tools/mxt2wazowski.py team.mxtsessions -o my-sessions/

# Several files, one tree each, into a parent folder
python3 tools/mxt2wazowski.py *.mxtsessions --outdir converted/

# Name the tree root (becomes the source's display name)
python3 tools/mxt2wazowski.py team.mxtsessions --prefix "Work servers"
```

The output is a Wazowski **session tree**: each folder is a directory with a
`.folder` sidecar, and each session is a `<slug>.wzsession` file inside it — the
same layout a [shared source](shared-sessions.md) reads. The tree root's
`.folder` is named after `--prefix` (or the input's filename); that becomes the
source's display name, which you can rename in Wazowski later.

## Using the result

- **As a git shared source**: commit the generated directory's contents at the
  repo root and point a new git shared source at the repo.
- **As a folder shared source**: point a new shared source at the generated
  directory.

The converter refuses to write into a directory that already has files, so
re-running won't silently mix old and new output — remove the directory first.

## What converts

| MobaXterm type | Wazowski |
|---|---|
| SSH | SSH |
| RDP | RDP |
| VNC | VNC |
| SFTP | SSH (an SSH session has an SFTP files tab) |
| Web, FTP, Serial, Telnet | *skipped* (no direct Wazowski protocol) |

Folders (MobaXterm's `SubRep` tree) become the directory tree. The converter
prints a summary of what it converted and what it skipped, so nothing disappears
silently.

## Credentials

MobaXterm never stores passwords in a `.mxtsessions` file, and Wazowski stores no
usernames in any file, so **no credentials are imported** — every converted
session uses the default prompt auth, and you set a vault password/key (and a
username, if you want it remembered) per session in Wazowski afterward. Sessions
that referenced a MobaXterm credential (e.g. `[corp-ad]`) are reported by name so
you know which ones to point at a [vault](vault.md) entry.
