class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.9"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.9/security-warden-darwin-arm64.tar.gz"
      sha256 "b233a98eb47db8b8afbfe9cbb6df7b7e86d85720f274b90cb3650bb32bd8d843"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.9/security-warden-darwin-amd64.tar.gz"
      sha256 "09d11c8c62f324a232ee71247e6d2dc4d0db513cce58907ecfe0ff96df4e63ff"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.9/security-warden-linux-arm64.tar.gz"
      sha256 "5f7d0873699a051ab8ebde91220c6e49c1c32309081fb5de3c8814ba17964d5c"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.9/security-warden-linux-amd64.tar.gz"
      sha256 "e77db13e5dc43502979086847b53df31bad73cd0060e1b36f7c67adbd46aae03"
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

  test do
    assert_match version.to_s, shell_output("#{bin}/security-warden version")
  end
end
