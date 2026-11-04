#!/bin/sh
# Builds "Security Warden.app" (macOS only: swiftc, lipo, iconutil).
#
#   scripts/make-app.sh VERSION CLI_BINARY OUT_DIR
#
# The app is a native window around the local web UI (packaging/macos/
# App.swift). CLI_BINARY (a universal security-warden) is copied inside it,
# so the app works without anything else installed. Signing happens in
# make-dmg.sh, with the rest of the release.
set -eu
version=$1
cli=$2
out=$3
here=$(cd "$(dirname "$0")/.." && pwd)
src="$here/packaging/macos"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

app="$out/Security Warden.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# Universal binary: Apple silicon and Intel, macOS 12 or later.
for arch in arm64 x86_64; do
  xcrun swiftc -O -target "$arch-apple-macos12" -o "$work/app-$arch" "$src/App.swift"
done
lipo -create -output "$app/Contents/MacOS/Security Warden" "$work/app-arm64" "$work/app-x86_64"

cp "$cli" "$app/Contents/Resources/security-warden"
chmod +x "$app/Contents/Resources/security-warden"

# Icon: draw once at 1024 px, scale to every size iconutil wants.
xcrun swift "$src/icon.swift" "$work/icon.png" >/dev/null
iconset="$work/AppIcon.iconset"
mkdir "$iconset"
for s in 16 32 128 256 512; do
  sips -z $s $s "$work/icon.png" --out "$iconset/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2))
  sips -z $d $d "$work/icon.png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

short=${version#v}
case $short in [0-9]*) ;; *) short=0.0.0 ;; esac
sed -e "s/@VERSION@/$short/g" "$src/Info.plist" > "$app/Contents/Info.plist"
echo "$app"
