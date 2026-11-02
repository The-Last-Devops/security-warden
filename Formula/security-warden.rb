class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.4"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.4/security-warden-darwin-arm64.tar.gz"
      sha256 "f9a93130f9705e0f1500ee15663a9fda70106e337be40ea780c1a1823357e11c"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.4/security-warden-darwin-amd64.tar.gz"
      sha256 "828ef0980e757e24d1a92f8c008dadb43e7066b0e1f12426e5d7fd50e02c5624"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.4/security-warden-linux-arm64.tar.gz"
      sha256 "fb9369c1e227257c912e04e390518f18bb58102c17192074a4d9e4c4fbe24873"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.4/security-warden-linux-amd64.tar.gz"
      sha256 "d5b333eb44fa809a98759e5c947c93c146229928784f055717ea28affc9c3ac9"
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
