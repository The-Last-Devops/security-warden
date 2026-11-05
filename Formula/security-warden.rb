class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.5.1"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.1/security-warden-darwin-arm64.tar.gz"
      sha256 "fa7c3a6ba1955f904e17f4834a0891912d12cf15074c7694e8a596e682d1e487"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.1/security-warden-darwin-amd64.tar.gz"
      sha256 "b499c8b00edc92e3f3eced4fb42875bc9e420ac3db1177e75c42fe4f2babfce7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.1/security-warden-linux-arm64.tar.gz"
      sha256 "b0381b9b6ce05e6ebe5277f36b1d0e35dcfeb26d714a124c0d980e566e6d119c"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.5.1/security-warden-linux-amd64.tar.gz"
      sha256 "c5281e2572daa07e55f6fe47ae8e723eaeabf61b5dd775cf013b767d7dc9eb5c"
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
