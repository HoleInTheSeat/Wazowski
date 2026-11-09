#!/usr/bin/env python3
"""Convert MobaXterm session files (.mxtsessions) to a Wazowski session tree.

MobaXterm stores sessions in an INI-style file: `[Bookmarks_N]` sections each
carry a `SubRep=` folder path (back-slash nested) and one `Name=#img#type%...`
line per session. Wazowski reads an exploded **directory tree**: every folder is
a directory with a `.folder` sidecar, and every session is a `<slug>.wzsession`
file inside its folder's directory. Directory and file names are slugs; the human
display name and a stable UUID live *inside* each file.

Usage:
    mxt2wazowski.py INPUT.mxtsessions [MORE.mxtsessions ...]
    mxt2wazowski.py INPUT.mxtsessions -o my-sessions/
    mxt2wazowski.py *.mxtsessions --outdir converted/ --prefix "Work servers"

Each input produces one output **directory** (the tree root; named `<input-stem>`
by default), ready to commit to a git repo or drop on a shared folder and point a
Wazowski shared source at. The tree root's `.folder` is named after `--prefix`
(or the input stem) — that becomes the source's display name, which you can
rename in Wazowski afterwards.

Credentials are never exported: MobaXterm `.mxtsessions` files hold no passwords,
and Wazowski stores no usernames in any file — every converted session uses the
default prompt auth, and you set a vault password/key (and username, if you want
it remembered) per session in Wazowski afterwards. Sessions that referenced a
MobaXterm credential (e.g. `[corp-ad]`) are reported so you know which need one.

Only SSH, RDP and VNC map to a Wazowski protocol (SFTP folds into SSH, since a
Wazowski SSH session has an SFTP files tab). Web, FTP, Telnet and Serial have no
Wazowski equivalent and are reported as skipped rather than silently dropped.
"""

from __future__ import annotations

import argparse
import secrets
import sys
import tomllib
from collections import Counter
from pathlib import Path

# MobaXterm session-type code (the second `#N`) -> what we do with it.
TYPE_SSH = 0
TYPE_TELNET = 1
TYPE_RDP = 4
TYPE_VNC = 5
TYPE_FTP = 6
TYPE_SFTP = 7
TYPE_SERIAL = 8
TYPE_WEB = 11

TYPE_NAMES = {
    TYPE_SSH: "SSH",
    TYPE_TELNET: "Telnet",
    2: "Rlogin",
    3: "Xdmcp",
    TYPE_RDP: "RDP",
    TYPE_VNC: "VNC",
    TYPE_FTP: "FTP",
    TYPE_SFTP: "SFTP",
    TYPE_SERIAL: "Serial",
    9: "File",
    10: "Browser",
    TYPE_WEB: "Web",
    12: "Mosh",
    13: "AWS S3",
    14: "WSL",
}

DEFAULT_PORT = {"ssh": 22, "rdp": 3389, "vnc": 5900}

# Tree-format constants (mirror wazowski-core's `session::tree`).
SESSION_EXT = "wzsession"
FOLDER_FILE = ".folder"


def new_id() -> str:
    """A 16-hex-char id, matching Wazowski's session/folder ids."""
    return secrets.token_hex(8)


class Converted:
    """One session ready to emit, plus notes gathered along the way."""

    def __init__(self, name, folder, protocol, host, port, username):
        self.id = new_id()
        self.name = name
        self.folder = folder
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username  # parsed for reference only; never emitted


def read_text(path: Path) -> str:
    """Read a MobaXterm file, tolerating BOMs and the usual Windows encodings."""
    data = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def norm_folder(subrep: str) -> str:
    """MobaXterm `A\\B\\C` -> Wazowski `A/B/C`; empty stays root."""
    subrep = subrep.strip().strip("\\")
    if not subrep:
        return ""
    parts = [p.strip() for p in subrep.split("\\") if p.strip()]
    return "/".join(parts)


def ancestors(folder: str) -> list[str]:
    """`A/B/C` -> [`A`, `A/B`, `A/B/C`], so intermediate folders exist in the tree."""
    if not folder:
        return []
    parts = folder.split("/")
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


def parse_value(value: str):
    """Split a session value `#img#type%f0%f1%...#MobaFont%...` into (type, [fields]).

    Returns None for non-session lines (SubRep=, ImgNum=, settings, blanks).
    """
    value = value.strip()
    if not value.startswith("#"):
        return None
    # The connection block is parts[2]: "type%host%port%user%..."; parts[3:] are
    # the appearance/terminal blocks (#MobaFont%...#...#...) we don't need.
    parts = value.split("#")
    if len(parts) < 3:
        return None
    fields = parts[2].split("%")
    try:
        stype = int(fields[0])
    except ValueError:
        return None
    return stype, fields[1:]


def norm_port(raw: str, protocol: str) -> int:
    raw = (raw or "").strip()
    if raw in ("", "-1", "0"):
        return DEFAULT_PORT[protocol]
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_PORT[protocol]


def norm_user(raw: str):
    """-> (username, credential_ref). A `[name]` ref yields a blank username."""
    raw = (raw or "").strip()
    if raw in ("", "-1"):
        return "", None
    if raw.startswith("[") and raw.endswith("]"):
        return "", raw[1:-1]
    return raw, None


def field(fields: list[str], idx: int) -> str:
    return fields[idx] if idx < len(fields) else ""


class Report:
    def __init__(self):
        self.converted = Counter()  # protocol -> count
        self.skipped = Counter()  # type name -> count
        self.cred_refs: dict[str, list[str]] = {}  # credential name -> session names

    def note_cred(self, ref: str, session_name: str):
        self.cred_refs.setdefault(ref, []).append(session_name)


def convert_file(path: Path, report: Report):
    """Parse one MobaXterm file. Returns (sessions, folders, allowed_editors)."""
    sessions: list[Converted] = []
    folders: set[str] = set()
    allowed_editors = ""
    current_section = None
    current_folder = ""  # folder for the section we're inside

    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
            # Blank or comment line (a leading '#' here is a file comment, not a
            # session value — session values live after `=`).
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            current_folder = ""  # reset until this section's SubRep is seen
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()

        if current_section == "SharedSettings":
            if key == "AllowedEditors":
                allowed_editors = value.strip()
            continue

        if key == "SubRep":
            current_folder = norm_folder(value)
            if current_folder:
                folders.update(ancestors(current_folder))
            continue
        if key == "ImgNum":
            continue

        parsed = parse_value(value)
        if parsed is None:
            continue
        stype, fields = parsed
        name = key.strip()
        folder = current_folder

        if stype in (TYPE_SSH, TYPE_SFTP):
            protocol = "ssh"
            host = field(fields, 0).strip()
            port = norm_port(field(fields, 1), "ssh")
            username, cred = norm_user(field(fields, 2))
        elif stype == TYPE_RDP:
            protocol = "rdp"
            host = field(fields, 0).strip()
            port = norm_port(field(fields, 1), "rdp")
            username, cred = norm_user(field(fields, 2))
        elif stype == TYPE_VNC:
            protocol = "vnc"
            host = field(fields, 0).strip()
            port = norm_port(field(fields, 1), "vnc")
            username, cred = "", None  # VNC authenticates by password, not user
        else:
            report.skipped[TYPE_NAMES.get(stype, f"type {stype}")] += 1
            continue

        if not host:
            report.skipped[f"{TYPE_NAMES.get(stype, stype)} (no host)"] += 1
            continue

        sessions.append(Converted(name, folder, protocol, host, port, username))
        report.converted[protocol] += 1
        if cred:
            report.note_cred(cred, name)

    return sessions, folders, allowed_editors


# ---- tree output -----------------------------------------------------------


def slugify(name: str) -> str:
    """Lowercase ASCII-alphanumeric slug, other runs collapsed to `-`, trimmed.

    Mirrors wazowski-core's `session::tree::slugify`; empty -> `item`.
    """
    out = []
    last_dash = True
    for ch in name.strip():
        if ch.isascii() and ch.isalnum():
            out.append(ch.lower())
            last_dash = False
        elif not last_dash:
            out.append("-")
            last_dash = True
    slug = "".join(out).rstrip("-")
    return slug or "item"


def unique_slug(base: str, used: set[str]) -> str:
    """A slug not already in `used`; appends `-2`, `-3`, … until free."""
    if base not in used:
        return base
    n = 2
    while f"{base}-{n}" in used:
        n += 1
    return f"{base}-{n}"


def slug_paths(folders: set[str]) -> dict[str, str]:
    """Map each display folder path to a slug directory path, unique among siblings.

    `sorted` puts parents before children (`a` < `a/b`), so a parent's slug is
    known when its children are assigned.
    """
    paths: dict[str, str] = {}
    used: dict[str, set[str]] = {}
    for disp in sorted(folders):
        parent_disp, _, name = disp.rpartition("/")
        parent = paths.get(parent_disp, "") if parent_disp else ""
        taken = used.setdefault(parent, set())
        slug = unique_slug(slugify(name), taken)
        taken.add(slug)
        paths[disp] = f"{parent}/{slug}" if parent else slug
    return paths


def toml_str(s: str) -> str:
    """Quote a value as a TOML basic string."""
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def folder_doc(name: str, description: str = "") -> str:
    lines = [f"id = {toml_str(new_id())}"]
    if name:
        lines.append(f"name = {toml_str(name)}")
    if description:
        lines.append(f"description = {toml_str(description)}")
    return "\n".join(lines) + "\n"


def session_doc(s: Converted) -> str:
    # No username and no auth: credentials are never exported, so the session gets
    # Wazowski's default prompt auth. Folder is implied by the directory.
    lines = [
        f"id = {toml_str(s.id)}",
        f"name = {toml_str(s.name)}",
        f"protocol = {toml_str(s.protocol)}",
        f"host = {toml_str(s.host)}",
        f"port = {s.port}",
    ]
    return "\n".join(lines) + "\n"


def render_tree(sessions, folders, root_name, source_name) -> list[tuple[str, str]]:
    """Build the tree as (relative path, file content) pairs."""
    files: list[tuple[str, str]] = []
    desc = f"Converted from MobaXterm ({source_name}). Set vault auth per session in Wazowski."
    files.append((FOLDER_FILE, folder_doc(root_name, desc)))

    paths = slug_paths(folders)
    for disp in sorted(folders):
        name = disp.rpartition("/")[2]
        files.append((f"{paths[disp]}/{FOLDER_FILE}", folder_doc(name)))

    used: dict[str, set[str]] = {}
    for s in sessions:
        parent = paths.get(s.folder, "") if s.folder else ""
        taken = used.setdefault(parent, set())
        slug = unique_slug(slugify(s.name), taken)
        taken.add(slug)
        rel = f"{parent}/{slug}.{SESSION_EXT}" if parent else f"{slug}.{SESSION_EXT}"
        files.append((rel, session_doc(s)))

    return files


def print_report(src: Path, dst: Path, report: Report, allowed_editors: str):
    print(f"\n{src.name} -> {dst}/ (tree)")
    total = sum(report.converted.values())
    if total:
        detail = ", ".join(f"{n} {p.upper()}" for p, n in sorted(report.converted.items()))
        print(f"  converted {total} session(s): {detail}")
    else:
        print("  converted 0 sessions")
    if report.skipped:
        detail = ", ".join(f"{n}x {t}" for t, n in sorted(report.skipped.items()))
        print(f"  skipped (no Wazowski protocol): {detail}")
    if report.cred_refs:
        print("  credential references (set a vault password/key for these in Wazowski):")
        for ref, names in sorted(report.cred_refs.items()):
            shown = ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")
            print(f"    [{ref}] -> {len(names)} session(s): {shown}")
    if allowed_editors:
        print(f"  (MobaXterm AllowedEditors, FYI, not used by Wazowski: {allowed_editors})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert MobaXterm .mxtsessions to a Wazowski session tree (a directory)."
    )
    ap.add_argument("inputs", nargs="+", type=Path, help="one or more .mxtsessions files")
    ap.add_argument(
        "-o", "--output", type=Path, help="output directory (only valid with a single input)"
    )
    ap.add_argument("--outdir", type=Path, help="parent directory to write <stem>/ trees into")
    ap.add_argument("--prefix", default="", help="name the tree root (the source's display name)")
    args = ap.parse_args(argv)

    if args.output and len(args.inputs) > 1:
        ap.error("-o/--output works with a single input; use --outdir for multiple")

    if args.outdir:
        args.outdir.mkdir(parents=True, exist_ok=True)

    rc = 0
    for src in args.inputs:
        if not src.is_file():
            print(f"error: {src} is not a file", file=sys.stderr)
            rc = 1
            continue

        report = Report()
        sessions, folders, allowed = convert_file(src, report)

        if args.output:
            dst = args.output
        elif args.outdir:
            dst = args.outdir / src.stem
        else:
            dst = src.with_suffix("")

        root_name = args.prefix.strip().strip("/") or src.stem
        files = render_tree(sessions, folders, root_name, src.name)

        # Validate every generated file parses as TOML before writing anything.
        bad = None
        for rel, content in files:
            try:
                tomllib.loads(content)
            except tomllib.TOMLDecodeError as e:
                bad = (rel, e)
                break
        if bad is not None:
            print(f"error: generated {bad[0]} for {src.name} is invalid: {bad[1]}", file=sys.stderr)
            rc = 1
            continue

        # Refuse to scribble into a non-empty directory (avoid mixing with old data).
        if dst.exists() and any(dst.iterdir()):
            print(f"error: {dst} already exists and is not empty; remove it first", file=sys.stderr)
            rc = 1
            continue

        for rel, content in files:
            out = dst / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content, encoding="utf-8")
        print_report(src, dst, report, allowed)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
