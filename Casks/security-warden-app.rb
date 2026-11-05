cask "security-warden-app" do
  version "1.5.1"
  sha256 "cf881204897abc809a1e08ff8251703d11adbb28746d3f649e59ad6d7ccfcdbd"

  url "https://github.com/The-Last-Devops/security-warden/releases/download/v#{version}/security-warden-v#{version}-macos.dmg"
  name "Security Warden"
  desc "App window for Security Warden, the local security checkup"
  homepage "https://github.com/The-Last-Devops/security-warden"

  depends_on formula: "the-last-devops/security-warden/security-warden"
  depends_on macos: ">= :monterey"

  app "Security Warden.app"

  # Only the window's own data; scans and settings belong to the formula.
  zap trash: [
    "~/Library/Caches/org.the-last-devops.security-warden.app",
    "~/Library/HTTPStorages/org.the-last-devops.security-warden.app",
    "~/Library/Preferences/org.the-last-devops.security-warden.app.plist",
    "~/Library/Saved Application State/org.the-last-devops.security-warden.app.savedState",
    "~/Library/WebKit/org.the-last-devops.security-warden.app",
  ]
end
