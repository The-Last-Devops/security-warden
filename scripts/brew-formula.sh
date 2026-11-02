#!/bin/sh
# Prints the Homebrew formula for a release.
#   scripts/brew-formula.sh v0.1.0 dist/SHA256SUMS > security-warden.rb
set -eu
tag=$1
sums=$2
version=${tag#v}
base="https://github.com/The-Last-Devops/security-warden/releases/download/${tag}"

sha() {
  s=$(awk -v f="security-warden-$1" '$2 == f || $2 == "*"f { print $1 }' "$sums")
  [ -n "$s" ] || { echo "no checksum for $1" >&2; exit 1; }
  echo "$s"
}

cat <<RUBY
class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "${version}"

  on_macos do
    on_arm do
      url "${base}/security-warden-darwin-arm64"
      sha256 "$(sha darwin-arm64)"
    end
    on_intel do
      url "${base}/security-warden-darwin-amd64"
      sha256 "$(sha darwin-amd64)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/security-warden-linux-arm64"
      sha256 "$(sha linux-arm64)"
    end
    on_intel do
      url "${base}/security-warden-linux-amd64"
      sha256 "$(sha linux-amd64)"
    end
  end

  def install
    bin.install Dir["security-warden-*"].first => "security-warden"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/security-warden version")
  end
end
RUBY
