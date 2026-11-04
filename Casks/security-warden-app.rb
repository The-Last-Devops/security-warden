cask "security-warden-app" do
  version "1.5.0"
  sha256 "e9097f14a06904d2ef411dda7173e1dffdce7f7c3138f12c4c81c6de7b1d52eb"

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
