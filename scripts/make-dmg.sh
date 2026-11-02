#!/bin/sh
# Builds dist/security-warden-<version>-macos.dmg from the two darwin
# binaries: one universal binary, an installer script and a README.
# Signs with a "Developer ID Application" certificate when MACOS_CERT_P12 is
# set, and notarizes with an App Store Connect API key when NOTARY_KEY_P8 is
# set. Without them the .dmg is unsigned and Gatekeeper blocks it.
#   scripts/make-dmg.sh v0.1.0 dist
set -eu
tag=$1
dist=$2
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

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
  codesign --force --options runtime --timestamp -s "$identity" "$stage/security-warden"
  codesign --verify --strict --verbose=2 "$stage/security-warden"
fi

cat > "$stage/Install.command" <<'SH'
#!/bin/sh
# Copies security-warden to /usr/local/bin (asks for your password).
here=$(cd "$(dirname "$0")" && pwd)
sudo mkdir -p /usr/local/bin
sudo cp "$here/security-warden" /usr/local/bin/security-warden
echo
echo "Installed. Open Terminal and run: security-warden"
echo "Đã cài. Mở Terminal và chạy: security-warden"
SH
chmod +x "$stage/Install.command"

cat > "$stage/README.txt" <<TXT
security-warden ${tag}

Double-click Install.command, or copy security-warden anywhere on your PATH.
Then run in Terminal:  security-warden

Nhấp đúp Install.command, hoặc chép security-warden vào thư mục trong PATH.
Rồi chạy trong Terminal:  security-warden

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
  fi
fi
ls -l "$out"
