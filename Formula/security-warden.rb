class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.1"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.1/security-warden-darwin-arm64.tar.gz"
      sha256 "5288b8c64cedf80211f4a5516de14a251882a484ca6339cb35ee40fb61a23874"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.1/security-warden-darwin-amd64.tar.gz"
      sha256 "29ed29beabd66efefde64835736138a913f12129664a263f43d55c02a8ff1d99"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.1/security-warden-linux-arm64.tar.gz"
      sha256 "cb000662f4d537e513308409f2446a6366530873caac6b6739cb8acbecfb2e2d"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.1/security-warden-linux-amd64.tar.gz"
      sha256 "207a6cd38200c7ce438c8c6d8c7d4db2a5f8c738fca05d98b3c4190068262cd0"
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
