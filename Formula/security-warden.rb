class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "1.3.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.3.0/security-warden-darwin-arm64.tar.gz"
      sha256 "5dcfe0767d22a879869e3068f1bb85f075bafef1594ff75a478b579a1a911d08"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.3.0/security-warden-darwin-amd64.tar.gz"
      sha256 "d6595036150402323379ae2d1338e0d745cc5505217d11ef40dde8ed3b5243b5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.3.0/security-warden-linux-arm64.tar.gz"
      sha256 "e340e645aa40a2b533bf7b8e39afd21e2ea9639126d421c815e7d12dbdfe027d"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v1.3.0/security-warden-linux-amd64.tar.gz"
      sha256 "1cd1025322074372a8fc726dc1ce990b2dd079cc0a26b1fac96ec4ce423742e0"
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
