#!/bin/sh
# Build the RWR Package Intelligence AppImage and its matching backend package.
#
#   packaging/appimage/build-appimage.sh --runtime RUNTIME --out DIR [--pkgrel N]
#
# RUNTIME is an AppImage type-2 runtime (the ELF part of any type-2 AppImage).
# Everything is built as the current user inside DIR: no sudo, no pacman -U,
# no network (cargo --offline, makepkg --noprepare). Nothing is installed.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RUNTIME=
OUT=
PKGREL=$(sed -n 's/^pkgrel=//p' "$ROOT/packaging/arch/PKGBUILD")
while [ $# -gt 0 ]; do
    case "$1" in
        --runtime) RUNTIME=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        --pkgrel) PKGREL=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$RUNTIME" ] && [ -n "$OUT" ] || { echo "usage: $0 --runtime FILE --out DIR [--pkgrel N]" >&2; exit 2; }
case "$PKGREL" in *[!0-9]*|'') echo "invalid pkgrel: $PKGREL" >&2; exit 2 ;; esac
[ "$(head -c 4 "$RUNTIME" | od -An -c | tr -d ' ')" = "177ELF" ] || { echo "runtime is not ELF" >&2; exit 2; }
[ "$(dd if="$RUNTIME" bs=1 skip=8 count=3 2>/dev/null)" = "$(printf 'AI\002')" ] || { echo "runtime is not an AppImage type-2 runtime" >&2; exit 2; }

VERSION="0.1.0-$PKGREL"
NAME=rwr-package-intelligence
EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || date +%s)}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
case "$OUT" in "$ROOT"|"$ROOT"/*) echo "--out must be outside the source tree" >&2; exit 2 ;; esac
[ ! -e "$OUT/RWR-Package-Intelligence-$VERSION-x86_64.AppImage" ] || { echo "refusing to overwrite an existing AppImage in $OUT" >&2; exit 1; }

echo "== 1/4 source snapshot ($VERSION)"
SNAP="$OUT/backend/$NAME-$VERSION-src.tar.gz"
mkdir -p "$OUT/backend"
tar -C "$ROOT" --transform "s,^,$NAME-0.1.0/," --sort=name --mtime="@$EPOCH" \
    --owner=0 --group=0 --numeric-owner \
    --exclude='*.before-*' --exclude='*.backup-*' --exclude='*.bak' --exclude='*.broken-*' \
    -czf "$SNAP" Cargo.toml Cargo.lock src assets LICENSE ASSETS-LICENSE.md README.md \
    packaging/systemd packaging/polkit packaging/arch/BACKEND-DEPLOYMENT.md packaging/arch/release-rustc.sh \
    packaging/appimage/INSTALL-APPIMAGE.md
SHA=$(sha256sum "$SNAP" | cut -d' ' -f1)
sed -e "s/@PKGREL@/$PKGREL/" -e "s/@SOURCE@/$(basename "$SNAP")/" -e "s/@SHA256@/$SHA/" \
    "$ROOT/packaging/arch-backend/PKGBUILD.in" > "$OUT/backend/PKGBUILD"

echo "== 2/4 build GUI + backend with makepkg (offline, as $(id -un))"
(cd "$OUT/backend" && CARGO_NET_OFFLINE=true SOURCE_DATE_EPOCH=$EPOCH \
    makepkg --noprepare --nodeps --force --cleanbuild --noconfirm)
PKG="$OUT/backend/$NAME-backend-$VERSION-x86_64.pkg.tar.zst"
[ -f "$PKG" ] || { echo "backend package missing" >&2; exit 1; }
GUI="$OUT/backend/src/$NAME-0.1.0/target/release/$NAME"
[ -x "$GUI" ] || { echo "GUI binary missing" >&2; exit 1; }

echo "== 3/4 AppDir"
APPDIR="$OUT/AppDir"
rm -rf "$APPDIR"
install -Dm755 "$ROOT/packaging/appimage/AppRun" "$APPDIR/AppRun"
install -Dm755 "$GUI" "$APPDIR/usr/bin/$NAME"
DESKTOP=io.github.runningwithrottweilers.PackageIntelligence
sed "s,^Exec=.*,Exec=$NAME," "$ROOT/packaging/arch/$DESKTOP.desktop" > "$APPDIR/$DESKTOP.desktop"
install -Dm644 "$ROOT/assets/icons/rwr-package-intelligence-256.png" "$APPDIR/$DESKTOP.png"
ln -s "$DESKTOP.png" "$APPDIR/.DirIcon"
B="$APPDIR/usr/share/$NAME/backend"
install -Dm644 "$PKG" "$B/$(basename "$PKG")"
(cd "$B" && sha256sum "$(basename "$PKG")" > "$(basename "$PKG").sha256")
printf '%s\n' "$VERSION" > "$B/VERSION"
install -Dm644 "$ROOT/packaging/appimage/INSTALL-APPIMAGE.md" "$B/INSTALL-APPIMAGE.md"
install -Dm644 "$ROOT/packaging/arch/BACKEND-DEPLOYMENT.md" "$B/BACKEND-DEPLOYMENT.md"
install -Dm644 "$ROOT/LICENSE" "$APPDIR/usr/share/licenses/$NAME/LICENSE"
install -Dm644 "$ROOT/ASSETS-LICENSE.md" "$APPDIR/usr/share/licenses/$NAME/ASSETS-LICENSE.md"
find "$APPDIR" -exec touch -h -d "@$EPOCH" {} +

echo "== 4/4 squashfs + runtime"
IMG="$OUT/RWR-Package-Intelligence-$VERSION-x86_64.AppImage"
env -u SOURCE_DATE_EPOCH mksquashfs "$APPDIR" "$OUT/AppDir.squashfs" -all-root -noappend -no-xattrs -comp zstd \
    -mkfs-time "$EPOCH" -all-time "$EPOCH" -quiet
cat "$RUNTIME" "$OUT/AppDir.squashfs" > "$IMG"
chmod 755 "$IMG"
rm -f "$OUT/AppDir.squashfs"
cp "$PKG" "$OUT/"
(cd "$OUT" && sha256sum "$(basename "$IMG")" > "$(basename "$IMG").sha256" &&
    sha256sum "$(basename "$PKG")" > "$(basename "$PKG").sha256")
echo "AppImage: $IMG"
echo "Backend:  $OUT/$(basename "$PKG")"
echo "Nothing was installed."
