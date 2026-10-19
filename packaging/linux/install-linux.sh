#!/usr/bin/env bash
#
# Install Wazowski's Linux desktop integration for the current user:
#   * a wazowski.desktop launcher (so it appears in the app menu), and
#   * the application icon in the hicolor theme at several sizes,
# so the window manager/taskbar shows the real icon instead of a generic one.
#
# The embedded window icon (main.rs, with_icon) already colours the window at the
# protocol level; this adds the *desktop* side that app menus and docks read.
#
# Usage:
#   packaging/linux/install-linux.sh [path/to/wazowski-binary]
#
# With no argument it uses target/release/wazowski if present, else whatever
# `wazowski` resolves to on PATH. It installs under $XDG_DATA_HOME (~/.local/share)
# and needs no root. The original icon.png is never modified.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
src_icon="$repo_root/icon.png"
desktop_src="$here/wazowski.desktop"

data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
apps_dir="$data_home/applications"
icons_root="$data_home/icons/hicolor"

# Resolve the binary to launch.
if [[ $# -ge 1 ]]; then
    bin="$1"
elif [[ -x "$repo_root/target/release/wazowski" ]]; then
    bin="$repo_root/target/release/wazowski"
elif command -v wazowski >/dev/null 2>&1; then
    bin="$(command -v wazowski)"
else
    echo "error: no wazowski binary given and none found (build with 'cargo build --release -p wazowski-app')" >&2
    exit 1
fi
bin="$(readlink -f "$bin")"

[[ -f "$src_icon" ]] || { echo "error: $src_icon not found" >&2; exit 1; }

echo "Binary: $bin"
echo "Icons:  $icons_root"
echo "Launch: $apps_dir/wazowski.desktop"

# Install the icon at standard sizes. Prefer a resizer so docks get a crisp icon;
# fall back to dropping the full-resolution PNG into a single size bucket.
install_icon() {
    local size="$1" dst="$icons_root/${size}x${size}/apps/wazowski.png"
    mkdir -p "$(dirname "$dst")"
    if command -v magick >/dev/null 2>&1; then
        magick "$src_icon" -resize "${size}x${size}" "$dst"
    elif command -v convert >/dev/null 2>&1; then
        convert "$src_icon" -resize "${size}x${size}" "$dst"
    else
        cp "$src_icon" "$dst"
    fi
}

if command -v magick >/dev/null 2>&1 || command -v convert >/dev/null 2>&1; then
    for size in 16 32 48 64 128 256 512; do
        install_icon "$size"
    done
else
    echo "note: ImageMagick not found; installing the full-size icon at 256x256 only" >&2
    install_icon 256
fi

# Write the launcher with an absolute Exec so it works from the app menu.
mkdir -p "$apps_dir"
sed "s|^Exec=.*|Exec=$bin|" "$desktop_src" > "$apps_dir/wazowski.desktop"
chmod 644 "$apps_dir/wazowski.desktop"

# Refresh caches so the new icon/launcher show up without a re-login.
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps_dir" || true
command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$icons_root" || true

echo "Done. If the icon doesn't appear immediately, log out and back in."
