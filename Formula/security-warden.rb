class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.3"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.3/security-warden-darwin-arm64.tar.gz"
      sha256 "d9e130d9e6dbbe8b0145efe031d1a38f0f31d909b2723d16e5ca0c32595cda2e"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.3/security-warden-darwin-amd64.tar.gz"
      sha256 "5640791fb6cc358af6f98b033d59fa9aefc3b13a6c37f3951479d24c0ec8e155"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.3/security-warden-linux-arm64.tar.gz"
      sha256 "9ae284e45fb99879e4f32bad26a7f8ac7677cd7a8caa5f25ed5f6c78fc752833"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.3/security-warden-linux-amd64.tar.gz"
      sha256 "016dcdd9c5242dc0538b8f00e6c069668997507b56adbe22d15ccd026fff0c7b"
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
