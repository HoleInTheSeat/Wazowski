# Importing from MobaXterm

If you're coming from MobaXterm, the `tools/mxt2wazowski.py` script converts a
MobaXterm sessions export (`.mxtsessions`) into a Wazowski sessions file you can
use directly or share with a team.

## Requirements

- Python 3.11+ (uses the standard library only — `tomllib`).

## Usage

```sh
# One file → team.toml next to it
python3 tools/mxt2wazowski.py team.mxtsessions

# Choose the output name
python3 tools/mxt2wazowski.py team.mxtsessions -o sessions.toml

# Several files into a folder
python3 tools/mxt2wazowski.py *.mxtsessions --outdir converted/

# Nest everything under one top-level folder
python3 tools/mxt2wazowski.py *.mxtsessions --outdir converted/ --prefix Work
```

The output is a Wazowski **store file** (`folders = [...]` plus `[[session]]`
tables) — exactly what a [shared source](shared-sessions.md) reads.

## Using the result

- **As a folder shared source**: point a new shared source (kind *Folder/file*) at
  the generated `.toml`.
- **As a git shared source**: commit the file into a repo and set it as the
  source's file.
- You can also merge the entries into your local sessions by moving them in from a
  shared source.

## What converts

| MobaXterm type | Wazowski |
|---|---|
| SSH | SSH |
| RDP | RDP |
| VNC | VNC |
| SFTP | SSH (an SSH session has an SFTP files tab) |
| Web, FTP, Serial, Telnet | *skipped* (no direct Wazowski protocol) |

Folders (MobaXterm's `SubRep` tree) are preserved. The converter prints a summary
of what it converted and what it skipped, so nothing disappears silently.

## Credentials

MobaXterm never stores passwords in a `.mxtsessions` file, so **no passwords are
imported** — every converted session uses the default (agent) auth. Sessions that
referenced a MobaXterm credential (e.g. `[corp-ad]`) are reported by name and left
with a blank username, so you know which ones to point at a
[vault](vault.md) entry afterward.
