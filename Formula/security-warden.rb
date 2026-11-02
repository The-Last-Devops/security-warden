class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.0/security-warden-darwin-arm64"
      sha256 "f92ebc8169ee88c0cbc169986297258454273eb5e68d608510c55fe05fadae1a"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.0/security-warden-darwin-amd64"
      sha256 "aab194b5a4a680669a9b75e5d20e26bb6b07e2c45793cce86fb8dc093d4fe22c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.0/security-warden-linux-arm64"
      sha256 "32c30733b5b8c5d13e365728c9286db990980d4a2d68c809bb3c6579678f5757"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.0/security-warden-linux-amd64"
      sha256 "66d7c8b16b8750e46a7a974ca4bb5f712e3917e2dac0b2ae1d2d3b36ec0f7a3b"
    end
  end

  def install
    bin.install Dir["security-warden-*"].first => "security-warden"
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
