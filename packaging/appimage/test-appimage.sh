#!/bin/sh
# Isolated checks of a built AppImage and backend package. Runs as the user,
# installs nothing, contacts no system service: runtime checks run in bwrap
# without /run (no system socket, no D-Bus, no Polkit) and without network.
#
#   packaging/appimage/test-appimage.sh OUT_DIR
set -eu
OUT=$(CDPATH= cd -- "${1:?usage: $0 OUT_DIR}" && pwd)
IMG=$(ls "$OUT"/RWR-Package-Intelligence-*-x86_64.AppImage)
PKG=$(ls "$OUT"/rwr-package-intelligence-backend-*-x86_64.pkg.tar.zst)
VERSION=$(basename "$PKG" | sed 's/^rwr-package-intelligence-backend-//; s/-x86_64.pkg.tar.zst$//')
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

(cd "$OUT" && sha256sum -c "$(basename "$IMG").sha256" >/dev/null && sha256sum -c "$(basename "$PKG").sha256" >/dev/null) || fail checksums
pass "checksums"

[ "$(dd if="$IMG" bs=1 skip=8 count=3 2>/dev/null)" = "$(printf 'AI\002')" ] || fail "not a type-2 AppImage"
OFFSET=$(python3 -I -c 'import struct,sys
d=open(sys.argv[1],"rb").read(4096); o=struct.unpack_from("<Q",d,0x28)[0]; e,n=struct.unpack_from("<HH",d,0x3A); print(o+e*n)' "$IMG")
LIST=$(unsquashfs -o "$OFFSET" -lls "$IMG")
echo "$LIST" | grep -q ' squashfs-root/usr/bin/rwr-package-intelligence$' || fail "GUI missing"
echo "$LIST" | grep -q "squashfs-root/usr/share/rwr-package-intelligence/backend/$(basename "$PKG")$" || fail "bundled backend missing"
echo "$LIST" | grep -qE 'squashfs-root/usr/lib/rwr-package-intelligence/|rwr-update-helper$|rwr-transaction-supervisor$|polkit-1|systemd/' && fail "privileged parts outside the backend package"
echo "$LIST" | grep -qE 'libalpm|libgpgme|libgtk' && fail "bundled system library"
echo "$LIST" | awk '{print $1}' | grep -q '^-..[sS]\|^-.....[sS]' && fail "setuid/setgid file"
echo "$LIST" | awk '{print $2}' | grep -vq '^root/root$' && fail "files not root-owned in image"
pass "AppImage layout: GUI only, backend only as a package, no setuid, no bundled libalpm/GTK"

unsquashfs -o "$OFFSET" -cat "$IMG" usr/share/rwr-package-intelligence/backend/"$(basename "$PKG")" | cmp -s - "$PKG" || fail "bundled backend differs from release backend"
pass "bundled backend is byte-identical to the release backend"

PKGINFO=$(bsdtar -xOf "$PKG" .PKGINFO)
echo "$PKGINFO" | grep -qx 'pkgname = rwr-package-intelligence-backend' || fail pkgname
echo "$PKGINFO" | grep -qx "pkgver = $VERSION" || fail pkgver
echo "$PKGINFO" | grep -qx 'conflict = rwr-package-intelligence' || fail conflicts
bsdtar -tf "$PKG" | grep -qx '.INSTALL' && fail "install script present"
FILES=$(bsdtar -tvf "$PKG")
for f in usr/lib/rwr-package-intelligence/rwr-update-helper usr/lib/rwr-package-intelligence/rwr-transaction-supervisor \
         usr/lib/systemd/system/rwr-package-intelligence-system.socket usr/lib/systemd/system/rwr-package-intelligence-system.service \
         usr/lib/systemd/user/rwr-package-intelligence.socket usr/lib/systemd/user/rwr-package-intelligence.service \
         usr/share/polkit-1/actions/io.github.runningwithrottweilers.rwr-package-intelligence.policy; do
    echo "$FILES" | grep -q " $f$" || fail "backend lacks $f"
done
echo "$FILES" | grep -q ' usr/bin/' && fail "backend ships the GUI"
echo "$FILES" | grep -qE ' etc/' && fail "backend ships /etc (execution policy must stay a deliberate admin step)"
echo "$FILES" | awk '{print $1}' | grep -q '^-..[sS]\|^-.....[sS]' && fail "setuid in backend"
echo "$FILES" | awk '$1 ~ /^-/ && $3" "$4 != "root root" {bad=1} END {exit !bad}' && fail "backend file not root-owned"
pass "backend package: supervisor, helper, units, Polkit; no GUI, no /etc, no install script, no setuid"

H=$HOME
sandbox() {
    bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /run --tmpfs /tmp --tmpfs "$H/.local/state" \
        --bind "$OUT" "$OUT" --unshare-all --die-with-parent \
        --setenv DBUS_SYSTEM_BUS_ADDRESS unix:path=/nonexistent --unsetenv DBUS_SESSION_BUS_ADDRESS \
        --setenv XDG_RUNTIME_DIR /tmp/xdg --setenv APPIMAGE_EXTRACT_AND_RUN 1 --setenv TMPDIR /tmp "$@"
}
INFO=$(sandbox "$IMG" --backend-info)
echo "$INFO" | grep -q "rwr-package-intelligence-backend-$VERSION-x86_64.pkg.tar.zst" || fail "--backend-info"
echo "$INFO" | grep -qi 'sudo pacman -U' || fail "--backend-info lacks install command"
pass "--backend-info in sandbox"
sandbox sh -c "mkdir -p /tmp/x && '$IMG' --extract-backend /tmp/x/b >/dev/null && cd /tmp/x/b && sha256sum -c *.sha256 >/dev/null" || fail "--extract-backend"
pass "--extract-backend in sandbox (verified copy, nothing installed)"
sandbox "$IMG" --help >/dev/null 2>&1 || fail "GUI --help"
pass "GUI binary starts (--help) in sandbox"
for word in sudo pkexec; do
    unsquashfs -o "$OFFSET" -cat "$IMG" AppRun | grep -v '^\s*#' | grep -v 'echo' | grep -q "$word" && fail "AppRun invokes $word"
done
pass "AppRun never invokes sudo/pkexec"
echo "ALL CHECKS PASSED"
