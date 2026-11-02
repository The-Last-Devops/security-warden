class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.6"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.6/security-warden-darwin-arm64.tar.gz"
      sha256 "051018d411664d905e8db4fb7f4b2ed00ec8facfbb1e7407c4685aa6fea930bb"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.6/security-warden-darwin-amd64.tar.gz"
      sha256 "f3d08e9c2c9afc37bd92cbd65b8916be2cc4fa8299d8130d59f0fc201a3bfe8a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.6/security-warden-linux-arm64.tar.gz"
      sha256 "d3ea499d188e9f5ca6b6bff4d291c8e1896e9713bec9424d405b114303f9ee2b"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.6/security-warden-linux-amd64.tar.gz"
      sha256 "6fa344a829197d3fb2f7c8f44c6b865b4a1e4a3450ca4b8bd1c8c12db5e7e4a5"
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
