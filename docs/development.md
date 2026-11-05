# Development

Everything builds in Docker; no Go or Node toolchain is needed on the host.

```sh
docker compose run --rm web      # build the web UI (needed before Go builds)
docker compose run --rm test     # gofmt, go vet + tests, including every rule's samples and the docs check
docker compose run --rm docs     # regenerate docs/what-it-checks.md after changing a rule
docker compose run --rm build    # ./dist/security-warden for this Mac
```

Development builds use port **7349** and their own data folder and service (`security-warden-dev`), so
they never collide with an installed release.

[AGENTS.md](../AGENTS.md) describes the layout and the rules every change must keep;
[Writing rules](writing-rules.md) covers adding a check.

## The macOS app

`packaging/macos/App.swift` is Security Warden.app: a WKWebView window that signs in through
`security-warden app-url`. It is built on macOS only (no Docker), with Xcode's command line tools:

```sh
go build -o dist/security-warden ./cmd/security-warden      # or docker compose run --rm build
scripts/make-app.sh dev dist/security-warden dist             # dist/Security Warden.app
./dist/security-warden serve --no-open &                      # the development server (port 7349)
open "dist/Security Warden.app" --env SW_CLI="$PWD/dist/security-warden"
```

`SW_CLI` tells the app which binary to ask for its sign-in link; `security-warden open` and `start` set it
to themselves, so a development build opens the development server. The page knows it runs in the app
from `window.swApp` (no passkeys there; "Sign in again" asks the app for a new ticket).

## Checks on every push

CI runs the same Dockerfile as a laptop (gofmt, `go vet` for Linux, macOS and Windows, all tests, the
check that [What it checks](what-it-checks.md) matches `rules/`), then a real scan on macOS, Linux and
Windows runners. Security scans run too: govulncheck and OSV-Scanner (vulnerable dependencies), gitleaks
(committed secrets), gosec and CodeQL (code analysis). Dependabot proposes dependency updates.

## Releases

Push a `v*` tag. GitHub Actions builds every platform, signs and notarizes the `.dmg` (and signs the macOS
binaries Homebrew installs, so Login Items lists the agent under the app), builds `.deb` and
`.rpm`, publishes the release and updates `Formula/security-warden.rb` (this repository is its own
Homebrew tap), then installs the release on macOS, Ubuntu, Debian and Fedora to check it.

## Roadmap

- Signed rule updates without a new release; self-update for direct binary installs.
- Docker image vulnerability scanning.
- An apt/dnf repository, so Linux installs update themselves.
- Real-time process and network events (Endpoint Security on macOS, ETW on Windows).
- Desktop app with a menu bar icon, sharing this web UI.
