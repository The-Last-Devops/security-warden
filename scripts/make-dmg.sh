#!/bin/sh
# Builds dist/security-warden-<version>-macos.dmg from the two darwin
# binaries: one universal binary, an installer script and a README. When
# signing, it also signs the two darwin binaries in dist and rebuilds their
# .tar.gz, so Homebrew installs a signed binary too.
# Signs with a "Developer ID Application" certificate when MACOS_CERT_P12 is
# set, and notarizes with an App Store Connect API key when NOTARY_KEY_P8 is
# set. Without them the .dmg is unsigned and Gatekeeper blocks it.
#   scripts/make-dmg.sh v0.1.0 dist
set -eu
tag=$1
dist=$2
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
sign_id=org.the-last-devops.security-warden

lipo -create -output "$stage/security-warden" \
  "$dist/security-warden-darwin-arm64" "$dist/security-warden-darwin-amd64"
chmod +x "$stage/security-warden"

if [ -n "${MACOS_CERT_P12:-}" ]; then
  kc="$RUNNER_TEMP/sign.keychain-db"
  security create-keychain -p ci "$kc"
  security set-keychain-settings -lut 3600 "$kc"
  security unlock-keychain -p ci "$kc"
  echo "$MACOS_CERT_P12" | base64 --decode > "$RUNNER_TEMP/cert.p12"
  security import "$RUNNER_TEMP/cert.p12" -k "$kc" -P "$MACOS_CERT_PASSWORD" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple: -s -k ci "$kc"
  security list-keychains -d user -s "$kc"
  identity=$(security find-identity -v -p codesigning "$kc" | awk -F'"' '/Developer ID Application/ { print $2; exit }')
  [ -n "$identity" ] || { echo "no Developer ID Application identity in MACOS_CERT_P12" >&2; exit 1; }
  codesign --force --options runtime --timestamp -s "$identity" -i "$sign_id" "$stage/security-warden"
  codesign --verify --strict --verbose=2 "$stage/security-warden"
  # The per-architecture binaries and their archives (Homebrew installs
  # these) get the same signature: macOS then lists the login item under the
  # app's name and developer (AssociatedBundleIdentifiers in the agent's
  # plist only counts for a binary from the app's team).
  for arch in arm64 amd64; do
    bin="$dist/security-warden-darwin-$arch"
    codesign --force --options runtime --timestamp -s "$identity" -i "$sign_id" "$bin"
    pkg=$(mktemp -d)
    cp "$bin" "$pkg/security-warden"
    tar -C "$pkg" -czf "$bin.tar.gz" security-warden
    rm -rf "$pkg"
  done
fi

# The app: a native window around the web UI, with the (signed) binary
# inside, so it works on its own. Signed inside out.
"$(dirname "$0")/make-app.sh" "$tag" "$stage/security-warden" "$stage" >/dev/null
if [ -n "${MACOS_CERT_P12:-}" ]; then
  codesign --force --options runtime --timestamp -s "$identity" "$stage/Security Warden.app"
  codesign --verify --deep --strict --verbose=2 "$stage/Security Warden.app"
fi

cat > "$stage/Install.command" <<'SH'
#!/bin/sh
# Copies security-warden to /usr/local/bin (asks for your password).
here=$(cd "$(dirname "$0")" && pwd)
sudo mkdir -p /usr/local/bin
sudo cp "$here/security-warden" /usr/local/bin/security-warden
# The app window (security-warden open and start show it).
sudo rm -rf "/Applications/Security Warden.app"
sudo ditto "$here/Security Warden.app" "/Applications/Security Warden.app"
echo
echo "Installed. Opening Security Warden…"
echo "Đã cài. Đang mở Security Warden…"
echo "(Keep this window open while you use it / Giữ cửa sổ này mở khi đang dùng)"
exec /usr/local/bin/security-warden serve
SH
chmod +x "$stage/Install.command"

cat > "$stage/README.txt" <<TXT
security-warden ${tag}

Double-click Install.command: it installs the Security Warden app in
Applications and the security-warden command in /usr/local/bin.
Or drag Security Warden.app to Applications and open it.

Nhấp đúp Install.command: lệnh cài app Security Warden vào Applications và
lệnh security-warden vào /usr/local/bin.
Hoặc kéo Security Warden.app vào Applications rồi mở nó.

https://github.com/The-Last-Devops/security-warden
TXT

out="$dist/security-warden-${tag}-macos.dmg"
hdiutil create -volname "security-warden ${tag}" -srcfolder "$stage" -format UDZO -ov "$out"

if [ -n "${MACOS_CERT_P12:-}" ]; then
  codesign --force --timestamp -s "$identity" "$out"
  if [ -n "${NOTARY_KEY_P8:-}" ]; then
    key="$RUNNER_TEMP/AuthKey.p8"
    echo "$NOTARY_KEY_P8" | base64 --decode > "$key"
    xcrun notarytool submit "$out" --key "$key" --key-id "$NOTARY_KEY_ID" \
      --issuer "$NOTARY_ISSUER_ID" --wait
    rm -f "$key"
    xcrun stapler staple "$out"
    spctl -a -t open --context context:primary-signature -vv "$out"
    # Only a notarized app goes to the Homebrew cask (release.yml).
    if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "notarized=true" >> "$GITHUB_OUTPUT"; fi
  fi
fi
ls -l "$out"
