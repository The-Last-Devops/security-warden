class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.8"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.8/security-warden-darwin-arm64.tar.gz"
      sha256 "6ca386e00d34f2d7ec0dafb77e7026e556d865d2db2e5e367114d7261042b1ff"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.8/security-warden-darwin-amd64.tar.gz"
      sha256 "5bf84bf016c7d39bc59fb6ba83fe3c742aa717ea30bdc21baba937bd936b3f40"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.8/security-warden-linux-arm64.tar.gz"
      sha256 "905767ee1aad4ded27857bda45866cbabd7e20b4a9a56f1f46f0a6968bb603d7"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.8/security-warden-linux-amd64.tar.gz"
      sha256 "2a763ee9b1cba2b02c74018bb9b173672ba328d5077cd69461fa28fabb38a0cb"
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
