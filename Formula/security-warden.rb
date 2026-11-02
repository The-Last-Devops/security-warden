class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.0.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.0.0/security-warden-darwin-arm64.tar.gz"
      sha256 "222584a02b929d329f0b2d8673e872f705bfd8caa1fac08d9ce246a63acab7bd"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.0.0/security-warden-darwin-amd64.tar.gz"
      sha256 "49866ad6d8e79a73234f9b1f8e1778907483af2def6102b30b12021b5de716e9"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.0.0/security-warden-linux-arm64.tar.gz"
      sha256 "29b6a33d7927b5c7ce0f40f4235678519aa3a63cb3aa0392d32f5661cce849f0"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.0.0/security-warden-linux-amd64.tar.gz"
      sha256 "7bc3d4a675cbec74cf56a03e9c34e98862a910aa0a321895daa4130c09152897"
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
