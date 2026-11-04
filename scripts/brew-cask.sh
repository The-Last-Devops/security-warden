#!/bin/sh
# Prints the Homebrew cask of the macOS app for a release.
#   scripts/brew-cask.sh v0.1.0 dist/SHA256SUMS > security-warden-app.rb
# The app comes from the release's signed and notarized .dmg; it needs the
# security-warden formula (the app is a window around it).
set -eu
tag=$1
sums=$2
version=${tag#v}
dmg="security-warden-${tag}-macos.dmg"
sha=$(awk -v f="$dmg" '$2 == f || $2 == "*"f { print $1 }' "$sums")
[ -n "$sha" ] || { echo "no checksum for $dmg" >&2; exit 1; }
id=org.the-last-devops.security-warden.app

cat <<RUBY
cask "security-warden-app" do
  version "${version}"
  sha256 "${sha}"

  url "https://github.com/The-Last-Devops/security-warden/releases/download/v#{version}/security-warden-v#{version}-macos.dmg"
  name "Security Warden"
  desc "App window for Security Warden, the local security checkup"
  homepage "https://github.com/The-Last-Devops/security-warden"

  depends_on formula: "the-last-devops/security-warden/security-warden"
  depends_on macos: ">= :monterey"

  app "Security Warden.app"

  # Only the window's own data; scans and settings belong to the formula.
  zap trash: [
    "~/Library/Caches/${id}",
    "~/Library/HTTPStorages/${id}",
    "~/Library/Preferences/${id}.plist",
    "~/Library/Saved Application State/${id}.savedState",
    "~/Library/WebKit/${id}",
  ]
end
RUBY
