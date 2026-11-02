class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.7"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.7/security-warden-darwin-arm64.tar.gz"
      sha256 "cbd35317f0c144ec1fe1e4b5e8bf7a99fbec2877e5b16c361a4b9000be4b43af"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.7/security-warden-darwin-amd64.tar.gz"
      sha256 "49ce53bb4218f7091fe017a27b6f2f9c4a580623d7091d4906b1e13984308a64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.7/security-warden-linux-arm64.tar.gz"
      sha256 "ea2e1e3dc7ef7d7d41fae3abf81193266d0210d3d9a49a0d1048d5efb41c4a97"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.7/security-warden-linux-amd64.tar.gz"
      sha256 "c8d6e0eecf55c88a5e7e394e6ee1a8fe2a5bbc81f5d464a924d608aba6765339"
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
