class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.2.1"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.1/security-warden-darwin-arm64.tar.gz"
      sha256 "39829e844a7951416e96973fba92eb3bc6c073e1f550032536e3030d7aedcc23"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.1/security-warden-darwin-amd64.tar.gz"
      sha256 "a5b2bcc082065ce78d73b4eac697de0ddd735186bebb893c481f3be378a8ed24"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.1/security-warden-linux-arm64.tar.gz"
      sha256 "780d2fe97db95d99b01e32f945f489708d506e3541592617ecf2837477d96b17"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.1/security-warden-linux-amd64.tar.gz"
      sha256 "47b64f6cebeaadb4d4ba6edfe7e357afbe547058eb53aab39c4f5d3b9ea1f622"
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
