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
  license "Apache-2.0"
  version "${version}"

  on_macos do
    on_arm do
      url "${base}/security-warden-darwin-arm64.tar.gz"
      sha256 "$(sha darwin-arm64.tar.gz)"
    end
    on_intel do
      url "${base}/security-warden-darwin-amd64.tar.gz"
      sha256 "$(sha darwin-amd64.tar.gz)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/security-warden-linux-arm64.tar.gz"
      sha256 "$(sha linux-arm64.tar.gz)"
    end
    on_intel do
      url "${base}/security-warden-linux-amd64.tar.gz"
      sha256 "$(sha linux-amd64.tar.gz)"
    end
  end

  def install
    bin.install "security-warden"
  end

  # brew services start security-warden: web UI on localhost:7348, scans
  # every 10 minutes, notifications for new problems.
  service do
    run [opt_bin/"security-warden", "serve", "--background"]
    keep_alive true
    log_path var/"log/security-warden.log"
    error_log_path var/"log/security-warden.log"
  end

  def caveats
    return unless OS.mac?

    <<~EOS
      For Security Warden in its own window (no browser tab, no passkey):
        brew install --cask the-last-devops/security-warden/security-warden-app
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/security-warden version")
  end
end
RUBY
