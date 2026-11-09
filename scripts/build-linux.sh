#!/usr/bin/env bash
#
# Build Wazowski's LINUX release artifacts locally — the raw binary, the Fedora
# RPM, and the portable AppImage — mirroring the Linux jobs in
# .github/workflows/release.yml, so you can test a real build without waiting on
# CI. Windows (.exe / installer) and macOS (.app / .dmg) must be built on those
# platforms, so they still come from CI.
#
# Usage:  scripts/build-linux.sh
# Output: dist/wazowski-v<version>-linux-x86_64{,.rpm,.AppImage}
#
# One-time prerequisites (Fedora):
#   sudo dnf install ImageMagick openssl-devel pkgconf-pkg-config wget file
#   cargo install cargo-generate-rpm --locked
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

ver=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
tag="v$ver"
echo "== Building Wazowski $tag (Linux artifacts) =="

echo "-- cargo build --release"
cargo build --release -p wazowski-app

echo "-- icons from icon.png"
convert=$(command -v magick || command -v convert)
for size in 16 32 48 64 128 256; do
    dir="packaging/linux/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$dir"
    "$convert" icon.png -resize "${size}x${size}" "$dir/wazowski.png"
done

mkdir -p dist
cp target/release/wazowski "dist/wazowski-${tag}-linux-x86_64"

echo "-- RPM"
# --auto-req disabled: the host is Fedora but we declare deps explicitly in the
# crate's [package.metadata.generate-rpm] (soname auto-detection is unreliable).
cargo generate-rpm -p crates/wazowski-app --auto-req disabled
cp "$(ls -t target/generate-rpm/*.rpm | head -1)" "dist/wazowski-${tag}-linux-x86_64.rpm"

echo "-- AppImage"
rm -rf AppDir
mkdir -p AppDir/usr/bin AppDir/usr/share/applications
cp target/release/wazowski AppDir/usr/bin/
cp packaging/linux/wazowski.desktop AppDir/usr/share/applications/
for size in 16 32 48 64 128 256; do
    d="AppDir/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$d"
    cp "packaging/linux/icons/hicolor/${size}x${size}/apps/wazowski.png" "$d/"
done
if [ ! -x linuxdeploy-x86_64.AppImage ]; then
    wget -q https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
    chmod +x linuxdeploy-x86_64.AppImage
fi
APPIMAGE_EXTRACT_AND_RUN=1 ./linuxdeploy-x86_64.AppImage --appdir AppDir \
    -d packaging/linux/wazowski.desktop \
    -i packaging/linux/icons/hicolor/256x256/apps/wazowski.png \
    --output appimage
cp "$(ls -t ./*.AppImage | grep -iv linuxdeploy | head -1)" "dist/wazowski-${tag}-linux-x86_64.AppImage"

echo
echo "== done — artifacts in dist/ =="
ls -lh dist/
