class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "0.2.12"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.12/security-warden-darwin-arm64.tar.gz"
      sha256 "fc08a5a0cfb9775ab58bfd52eace3bb6cc87d09d9813094da1c008d42be3f09a"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.12/security-warden-darwin-amd64.tar.gz"
      sha256 "f194b3ef93dbe31c49b98644604144067bc143d54b9ff27577368265280a6e6a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.12/security-warden-linux-arm64.tar.gz"
      sha256 "34c2de6ba6b6002902eae6244651eeddf4ce5df46873732d06cd9acc03352def"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.12/security-warden-linux-amd64.tar.gz"
      sha256 "00a34e04a24cd327b3c7f4c9faceb3fe4a25504aa013b42253a99104da6829e4"
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
