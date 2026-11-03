class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.4.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.4.0/security-warden-darwin-arm64.tar.gz"
      sha256 "0d0b3fffecbd8f6618d90c5e2e63f1007974523648758e59b10d069895b6a282"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.4.0/security-warden-darwin-amd64.tar.gz"
      sha256 "c945fa0e7dd5b55a1a31793554ec03869f2a1d34410e1669a78d25914c010e8e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.4.0/security-warden-linux-arm64.tar.gz"
      sha256 "2bd33676ec868e86ee1ba7b127ce1c8fe3c9cd018dc81f04cbbab441e3bad83f"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.4.0/security-warden-linux-amd64.tar.gz"
      sha256 "97ed4fc9889a4401b56fc37224a4c3c28cefadded3236077c4858aafaba832b3"
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
