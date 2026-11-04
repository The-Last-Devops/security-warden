class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.5.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.0/security-warden-darwin-arm64.tar.gz"
      sha256 "8e6a2f4204c346341e372f82696d0c807e64d09dc991dc55647448ef66d949c6"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.0/security-warden-darwin-amd64.tar.gz"
      sha256 "719ed5619b8497d013d6108fb6d3f1e258fd873cf445fb20ef3d95052dc76571"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.0/security-warden-linux-arm64.tar.gz"
      sha256 "a31dd2a5cbef3137c9cdfec369c860c00a7c98183a325f6e669f81b0f5786000"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.0/security-warden-linux-amd64.tar.gz"
      sha256 "138fdd76a4f9b72b92ee9fee7e532099b737e79a3678814df9bbeb9a4a8d170f"
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

  def caveats
    return unless OS.mac?

    <<~EOS
      For Security Warden in its own window (no browser tab, no passkey):
        brew install --cask the-last-devops/security-warden/security-warden-app
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/security-warden version")
  end
end
