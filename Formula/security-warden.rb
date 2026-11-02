class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.5"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.5/security-warden-darwin-arm64.tar.gz"
      sha256 "807dc79db612df50dd835377bd7fdeec8bc70bebd7ec92e9d1a93db5112798bc"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.5/security-warden-darwin-amd64.tar.gz"
      sha256 "abd7ab4ed0875928d4d502e5003c9e9714fef68fc0af81f6bff7c13a6ac2280b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.5/security-warden-linux-arm64.tar.gz"
      sha256 "324f7677f94ef2649cb2bc46dbb47ed75448db9ad500a5d79b31fe3924e3b56d"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.5/security-warden-linux-amd64.tar.gz"
      sha256 "b9087abb3e2af331f8a84692a2c0efb36f3d6985592d5390106ae3e8173b4cf6"
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
