# Install, update and uninstall

Security Warden is one self-contained program. Pick one way to install it.

## One line per system

These are the commands from the README's Quick start; CI runs the Linux ones on
Ubuntu, Debian and Fedora after every release, and starts, checks and stops the
background service on Windows on every push.

| System | Command |
|---|---|
| macOS | `brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden && brew trust the-last-devops/security-warden && brew install security-warden && security-warden start` |
| Ubuntu, Debian | `wget -qO /tmp/security-warden.deb https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden_$(dpkg --print-architecture).deb && sudo apt install -y /tmp/security-warden.deb && security-warden start` |
| Fedora, RHEL | `sudo dnf install -y https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-$(uname -m).rpm && security-warden start` |
| Windows (PowerShell) | `iwr https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-windows-amd64.exe -OutFile "$env:LOCALAPPDATA\security-warden.exe"; & "$env:LOCALAPPDATA\security-warden.exe" start` |

The Linux and Windows lines download from GitHub Releases over HTTPS. Releases also
publish `SHA256SUMS` if you want to check the file first (see Binaries below).
On Linux, `.deb`/`.rpm` installs do not update themselves yet: run the same line
again for a new version, or use Homebrew.

## Homebrew (macOS, Linux)

```sh
brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden
brew trust the-last-devops/security-warden
brew install security-warden
security-warden start
```

This repository is its own Homebrew tap; `brew trust` is needed once for third-party taps. `start` runs
Security Warden in the background, starts it again at login and opens your browser, already signed in.
The first time, it asks you to add a passkey (Touch ID, Windows Hello or a security key). After that,
`security-warden open` brings it back.

On macOS, add the app window (no browser tab, no passkey); it installs the formula too if needed:

```sh
brew install --cask the-last-devops/security-warden/security-warden-app
```

With the app installed, `start`, `open` and the popups show it instead of the browser, and
`security-warden update` (and the daily automatic update) upgrade the app along with the formula. The app
always talks to the installed `security-warden`, so it never starts a second background service next to
`brew services`.

Installed before the app existed? With automatic updates on, the new version installs the app once, a few
minutes after it starts, and says so in a notification. It never puts back an app you removed. Turn this
off in Settings → Updates or with `security-warden app auto off`. With automatic updates off, the web UI
offers an **Install the app** button (once, until you dismiss it), and `security-warden app install` does
the same.

## macOS disk image

Download `security-warden-<version>-macos.dmg` from
[Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), open it and double-click
`Install.command`. It copies the program to `/usr/local/bin/security-warden` and the **Security Warden app**
to `/Applications` (it asks for your password), then opens the app while the Terminal window stays open. Run
`security-warden start` to keep it running in the background instead. Everything is signed and notarized by
Apple.

The app is one native window around the same web UI: `security-warden open`, `start` and serious-problem
popups show it (not a browser tab), and opening it again brings the same window back. It signs in by itself
through the `security-warden` binary, so it never asks for a passkey (see
[Security model](security-model.md#signing-in)). Without the app (Homebrew, Linux, Windows, or `serve --tab`)
the default browser is used.

## Debian, Ubuntu

Download `security-warden_<version>_amd64.deb` (or `arm64`) from
[Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), then:

```sh
sudo apt install ./security-warden_*.deb
security-warden start
```

## Fedora, RHEL, openSUSE

Download the `.rpm` for your architecture from
[Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), then:

```sh
sudo rpm -i security-warden-*.rpm
security-warden start
```

The `.deb` and `.rpm` packages install `/usr/bin/security-warden`.

## Binary (macOS, Linux, Windows)

Download an archive from [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest) and
check it against `SHA256SUMS` from the same release:

```sh
curl -LO https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-darwin-arm64.tar.gz
curl -LO https://github.com/The-Last-Devops/security-warden/releases/latest/download/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS     # Linux: sha256sum --ignore-missing -c SHA256SUMS
tar xzf security-warden-darwin-arm64.tar.gz
./security-warden start
```

Other files: `darwin-amd64`, `linux-amd64`, `linux-arm64` (`.tar.gz`) and `security-warden-windows-amd64.exe`.
Move the program to a folder on your `PATH` so `security-warden` works from anywhere.

On Windows, `start` runs Security Warden as a background process; it does not start again at login yet.

## From source

Everything builds in Docker; no Go or Node toolchain is needed on the host.

```sh
docker build --target export --output dist .
```

This runs the tests and writes every platform's binary and `SHA256SUMS` to `dist/`. See
[Development](development.md) for day-to-day commands.

## Update

Homebrew installs **update themselves**: the background service checks once a day and runs
`brew upgrade security-warden`, then restarts on the new version. Turn it off with
`security-warden update off` (or in ⚙ Settings), and on again with `security-warden update on`.
To update right away, use either:

```sh
security-warden update                                  # upgrades and restarts the service
brew upgrade security-warden && security-warden start   # the same, by hand
```

Other installs (disk image, `.deb`, `.rpm`, binary) get a notification when a new release is out;
`security-warden update` tells you which version to get. Install it the same way as the first time.
Passkeys, hidden findings and settings are kept.

The update check only asks GitHub which release is the latest; nothing about your machine is sent.
See [Security model](security-model.md#network-access).

## Uninstall

Run `stop` first, so no login item is left behind:

```sh
security-warden stop
```

Then remove the program:

| Installed with | Remove with |
|---|---|
| Homebrew | `brew uninstall security-warden && brew untap the-last-devops/security-warden` |
| Disk image | `sudo rm /usr/local/bin/security-warden` |
| `.deb` | `sudo apt remove security-warden` |
| `.rpm` | `sudo rpm -e security-warden` |
| Binary | Delete the file you downloaded |

`stop` removes the login item: `~/Library/LaunchAgents/org.the-last-devops.security-warden.plist` on macOS,
`~/.config/systemd/user/security-warden.service` on Linux. On Windows it ends the background process.

### Also delete its data

Passkeys, sessions, hidden findings, the fix journal, settings, vulnerability data and logs:

```sh
# macOS
rm -rf ~/Library/Application\ Support/security-warden ~/Library/Logs/security-warden.log
# Linux
rm -rf ~/.config/security-warden ~/.local/state/security-warden
```

```powershell
# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:APPDATA\security-warden"
```

On Linux the data folder follows `$XDG_CONFIG_HOME` when it is set. Development builds use
`security-warden-dev` in place of `security-warden` in every path above.
