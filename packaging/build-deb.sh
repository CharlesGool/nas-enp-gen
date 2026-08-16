#!/usr/bin/env bash
# Build nas-enp-gen_<version>_amd64.deb from a PyInstaller onefile binary.
# Usage: packaging/build-deb.sh <version> [python-bin]
#   version:    e.g. 0.1.0 (no leading "v")
#   python-bin: interpreter with pyinstaller+PySide6+cryptography installed
#               (defaults to "python3" on PATH)
set -euo pipefail

VERSION="${1:?usage: build-deb.sh <version> [python-bin]}"
PYTHON="${2:-python3}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[1/4] Building onefile binary with PyInstaller ..."
"$PYTHON" -m PyInstaller \
    --distpath "$WORK/dist" --workpath "$WORK/build" --noconfirm \
    "$REPO_ROOT/packaging/nas-enp-gen.spec"

PKG_ROOT="$WORK/pkg"
mkdir -p "$PKG_ROOT/DEBIAN" "$PKG_ROOT/usr/bin" "$PKG_ROOT/usr/share/applications"

echo "[2/4] Assembling package tree ..."
install -m 0755 "$WORK/dist/nas-enp-gen" "$PKG_ROOT/usr/bin/nas-enp-gen"

cat > "$PKG_ROOT/usr/share/applications/nas-enp-gen.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=nas-enp-mount generator
Comment=Generate an encrypted NAS auto-mount client script
Exec=/usr/bin/nas-enp-gen
Terminal=false
Categories=System;Utility;
EOF

INSTALLED_SIZE_KB="$(du -sk "$PKG_ROOT" | cut -f1)"

# Runtime libs PySide6's bundled Qt binaries link against but PyInstaller
# does not (and should not) vendor, since they're expected to come from the
# base OS / X11 stack. Derived from `ldd` against the actual built
# libqxcb.so platform plugin on this dev host (Ubuntu 22.04) — apt resolves
# each of these packages' own further transitive deps automatically, so this
# list only needs the direct ones, not the full ldd closure. NOT verified
# across every Debian/Ubuntu release; if `nas-enp-gen` fails to start on a
# target with a Qt platform plugin error, run `ldd` against the installed
# binary's libqxcb.so there and adjust this list.
cat > "$PKG_ROOT/DEBIAN/control" <<EOF
Package: nas-enp-gen
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: ${INSTALLED_SIZE_KB}
Depends: libc6, libx11-6, libx11-xcb1, libxau6, libxdmcp6, libxkbcommon0, libxkbcommon-x11-0, libxcb1, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render0, libxcb-render-util0, libxcb-shape0, libxcb-shm0, libxcb-sync1, libxcb-util1, libxcb-xfixes0, libxcb-xkb1, libfontconfig1, libfreetype6, libdbus-1-3, libgl1, libglib2.0-0
Maintainer: CharlesGool <38390221+CharlesGool@users.noreply.github.com>
Description: GUI/CLI generator for encrypted NAS auto-mount client scripts
 Collects NAS connection details and mount mappings, encrypts them, and
 writes out a self-contained Python client script for deployment to
 Debian/Ubuntu Linux clients. See the project README for details.
EOF

echo "[3/4] Building .deb ..."
OUT_DEB="$REPO_ROOT/nas-enp-gen_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$OUT_DEB"

echo "[4/4] Done: $OUT_DEB"
du -h "$OUT_DEB"
