class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  license "Apache-2.0"
  version "0.2.10"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.10/security-warden-darwin-arm64.tar.gz"
      sha256 "7519619ed791b06e718bdadb93af2f5364cab203ab525a1200b7a799fe1b5886"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.10/security-warden-darwin-amd64.tar.gz"
      sha256 "e9317feb2f1ec03b14a48362eacebbd73d828f6a0988ad561fe84d7e3a5357f7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.10/security-warden-linux-arm64.tar.gz"
      sha256 "1e68a398f01e82c4fd97bcc48e6c98447b26858f237f15d9e7dc20f96591203d"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.2.10/security-warden-linux-amd64.tar.gz"
      sha256 "e33319cfdffe4dd360c76a0c458d689da1843efddd1fd056a47f6066a733dc30"
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
