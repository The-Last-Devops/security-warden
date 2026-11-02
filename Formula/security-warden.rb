class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.2.2"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.2/security-warden-darwin-arm64.tar.gz"
      sha256 "ae60501537b24eacb91123127f8e7389806010c02a8df44e94d0c384abe7336d"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.2/security-warden-darwin-amd64.tar.gz"
      sha256 "a74a1835dc70b608d99f1f50598e1ff5dcbca6416693235138b8578cb5063e78"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.2/security-warden-linux-arm64.tar.gz"
      sha256 "b46720e87e3036fba12a4c9f2816223a48f158c9183fe8ae67cff6b27e6828e4"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.2/security-warden-linux-amd64.tar.gz"
      sha256 "c0163bf16668496eecd57dd5d8b8b2589ee8e8a0d1db379a96ff1acb91873cff"
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
