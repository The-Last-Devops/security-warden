class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.2.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.0/security-warden-darwin-arm64.tar.gz"
      sha256 "b4fdf61c708fcb5dbef5b64f827cd8e6158787ef05f023d79740eb526234c470"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.0/security-warden-darwin-amd64.tar.gz"
      sha256 "5ebc6048cc716b8a3b64ac2c77f1142fb15796200eda5237122dd9e095dc4c45"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.0/security-warden-linux-arm64.tar.gz"
      sha256 "f61f275c0d5a6380bce64194dc33ec82e37b7f416cdd5810e10abbf384a2229c"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.2.0/security-warden-linux-amd64.tar.gz"
      sha256 "5f33e97ab525dc4f1c558e4e2cdf04cb9b3cb3fbb3e81458e4b628713d416978"
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
