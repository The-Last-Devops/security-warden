class SecurityWarden < Formula
  desc "Checks your machine for open doors and secrets lying around"
  homepage "https://github.com/The-Last-Devops/security-warden"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.1.0/security-warden-darwin-arm64"
      sha256 "683c1068a79b2756ab679c82533d40249359239492ab558c9d1d370c70f3c9bd"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.1.0/security-warden-darwin-amd64"
      sha256 "63b822404082241ea9d51fc945689d8f9e2b6607dec041923074fe7bd255b5c6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.1.0/security-warden-linux-arm64"
      sha256 "2908c81942baa9ebb663999b623f408dd839e64ed01801b1216357816371e6fb"
    end
    on_intel do
      url "https://github.com/The-Last-Devops/security-warden/releases/download/v0.1.0/security-warden-linux-amd64"
      sha256 "b38bdb015856a04b7843810e3f033aa49fdc87623160a23d9a43170ab3d3f2bb"
    end
  end

  def install
    bin.install Dir["security-warden-*"].first => "security-warden"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/security-warden version")
  end
end
