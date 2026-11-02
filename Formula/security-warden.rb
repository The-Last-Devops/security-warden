class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.1.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.1.0/security-warden-darwin-arm64.tar.gz"
      sha256 "aedeb095112a966ab06d26ef11f29853ae3e61f2a6d26e3e39699a4a598dbce2"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.1.0/security-warden-darwin-amd64.tar.gz"
      sha256 "024b3693f0d61fb565f4f9318a62cf91507e9c0f547c79485139f358a0d91fc7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.1.0/security-warden-linux-arm64.tar.gz"
      sha256 "4d3434f846bb9915de95103d2afa0491a7d089181e4a172c20bac4775e32d4bc"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.1.0/security-warden-linux-amd64.tar.gz"
      sha256 "104731b31b1befe5fe46c78b3331b25244e37faa9fcb17fe88dfb07a1af281e1"
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
