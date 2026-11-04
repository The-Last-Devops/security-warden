// Security Warden.app: one native window around the local web UI.
//
// The window signs itself in: it runs the security-warden binary
// (`security-warden app-url`), which reads the server secret (a 0600 file)
// and prints a one-time sign-in link. So no passkey is needed here, and the
// server still listens on loopback only, as for the browser.
//
// Which binary: $SW_CLI (set by `security-warden open`/`start`, so a
// development build opens the development server), else the installed one
// (Homebrew, then the .dmg's /usr/local/bin), so the app talks to the server
// that install runs and never starts a second background service next to
// `brew services`; the copy inside this app only when nothing is installed.
//
// Build: scripts/make-app.sh. No dependencies beyond AppKit and WebKit.

import AppKit
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate,
    WKScriptMessageHandler, WKDownloadDelegate
{
    var window: NSWindow!
    var web: WKWebView!
    var status: NSTextField!
    var host = "localhost"
    var port = 0

    func applicationDidFinishLaunching(_ note: Notification) {
        buildMenu()
        let cfg = WKWebViewConfiguration()
        // The page asks the app to sign in again (window.swApp.signIn())
        // when its session has ended; it also hides passkeys when it sees
        // window.swApp.
        let js = "window.swApp = { signIn: () => window.webkit.messageHandlers.sw.postMessage('signin') };"
        cfg.userContentController.addUserScript(WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        cfg.userContentController.add(self, name: "sw")
        web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.isHidden = true

        status = NSTextField(labelWithString: "Security Warden…")
        status.font = .systemFont(ofSize: 15)
        status.textColor = .secondaryLabelColor
        status.alignment = .center
        status.translatesAutoresizingMaskIntoConstraints = false

        let root = NSView()
        web.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(web)
        root.addSubview(status)
        NSLayoutConstraint.activate([
            web.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            web.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            web.topAnchor.constraint(equalTo: root.topAnchor),
            web.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            status.centerXAnchor.constraint(equalTo: root.centerXAnchor),
            status.centerYAnchor.constraint(equalTo: root.centerYAnchor),
            status.widthAnchor.constraint(lessThanOrEqualTo: root.widthAnchor, constant: -48),
        ])

        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Security Warden"
        window.minSize = NSSize(width: 420, height: 480)
        window.contentView = root
        window.center()
        window.setFrameAutosaveName("SecurityWardenMain")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        signIn()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool { true }

    // Opened again (Dock, `security-warden open`): bring the one window up.
    func applicationShouldHandleReopen(_ app: NSApplication, hasVisibleWindows: Bool) -> Bool {
        window.makeKeyAndOrderFront(nil)
        return true
    }

    // MARK: signing in

    // Candidates in order; each must be executable. An older install that
    // has no `app-url` yet fails it, and the next one is tried.
    func clis() -> [String] {
        var paths: [String] = []
        if let p = ProcessInfo.processInfo.environment["SW_CLI"], !p.isEmpty { paths.append(p) }
        paths += ["/opt/homebrew/bin/security-warden", "/usr/local/bin/security-warden"]
        if let p = Bundle.main.path(forResource: "security-warden", ofType: nil) { paths.append(p) }
        var seen = Set<String>()
        return paths.filter { FileManager.default.isExecutableFile(atPath: $0) && seen.insert($0).inserted }
    }

    // Runs `BIN app-url`: the sign-in link, or why there is none.
    func appURL(_ bin: String) -> (URL?, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["app-url"]
        let out = Pipe(), errOut = Pipe()
        p.standardOutput = out
        p.standardError = errOut
        do { try p.run() } catch { return (nil, error.localizedDescription) }
        // Read before waiting: a full pipe would block the child.
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let problem = String(decoding: errOut.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        if p.terminationStatus == 0, let url = URL(string: text), url.host == "localhost", url.port != nil {
            return (url, "")
        }
        return (nil, problem.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func signIn() {
        let bins = clis()
        if bins.isEmpty {
            show("Security Warden is not installed: security-warden was not found.")
            return
        }
        show("Security Warden…")
        DispatchQueue.global().async {
            var problem = ""
            for bin in bins {
                let (url, why) = self.appURL(bin)
                if let url {
                    DispatchQueue.main.async {
                        self.port = url.port!
                        self.web.isHidden = false
                        self.status.isHidden = true
                        self.web.load(URLRequest(url: url))
                    }
                    return
                }
                if problem.isEmpty || !why.isEmpty && !why.hasPrefix("security-warden:") { problem = why }
            }
            DispatchQueue.main.async {
                self.show(problem.isEmpty ? "Security Warden did not start." : problem)
            }
        }
    }

    func show(_ text: String) {
        status.stringValue = text
        status.isHidden = false
        web.isHidden = true
    }

    func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.body as? String == "signin" { signIn() }
    }

    // MARK: navigation: only the local server stays in the window

    func isLocal(_ url: URL?) -> Bool {
        guard let url else { return false }
        return url.scheme == "http" && url.host == host && url.port == port
    }

    func webView(_ w: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if action.shouldPerformDownload {
            decisionHandler(.download)
        } else if isLocal(action.request.url) || action.request.url?.scheme == "about" {
            decisionHandler(.allow)
        } else {
            // GitHub issue links, docs: the default browser.
            if let url = action.request.url { NSWorkspace.shared.open(url) }
            decisionHandler(.cancel)
        }
    }

    func webView(_ w: WKWebView, decidePolicyFor response: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        let disposition = (response.response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Disposition") ?? ""
        decisionHandler(disposition.lowercased().hasPrefix("attachment") || !response.canShowMIMEType ? .download : .allow)
    }

    // target="_blank": never a second window.
    func webView(_ w: WKWebView, createWebViewWith c: WKWebViewConfiguration, for action: WKNavigationAction,
                 windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = action.request.url {
            if isLocal(url) { w.load(action.request) } else { NSWorkspace.shared.open(url) }
        }
        return nil
    }

    func webView(_ w: WKWebView, didFailProvisionalNavigation n: WKNavigation!, withError error: Error) {
        show(error.localizedDescription)
    }

    // MARK: downloads (the scan log) go to ~/Downloads

    func webView(_ w: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ w: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func download(_ d: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename name: String,
                  completionHandler: @escaping (URL?) -> Void) {
        let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let base = (name as NSString).deletingPathExtension, ext = (name as NSString).pathExtension
        var url = dir.appendingPathComponent(name)
        var n = 2
        while FileManager.default.fileExists(atPath: url.path) {
            url = dir.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            n += 1
        }
        completionHandler(url)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    }

    // MARK: menu (Edit makes copy and paste work in the page)

    func buildMenu() {
        let main = NSMenu()
        func sub(_ title: String, _ items: [NSMenuItem]) {
            let item = NSMenuItem()
            let menu = NSMenu(title: title)
            items.forEach(menu.addItem)
            item.submenu = menu
            main.addItem(item)
        }
        func it(_ title: String, _ sel: Selector?, _ key: String, _ mods: NSEvent.ModifierFlags = .command) -> NSMenuItem {
            let i = NSMenuItem(title: title, action: sel, keyEquivalent: key)
            i.keyEquivalentModifierMask = mods
            return i
        }
        sub("Security Warden", [
            it("About Security Warden", #selector(NSApplication.orderFrontStandardAboutPanel(_:)), ""),
            .separator(),
            it("Hide Security Warden", #selector(NSApplication.hide(_:)), "h"),
            it("Hide Others", #selector(NSApplication.hideOtherApplications(_:)), "h", [.command, .option]),
            .separator(),
            it("Quit Security Warden", #selector(NSApplication.terminate(_:)), "q"),
        ])
        sub("Edit", [
            it("Undo", Selector(("undo:")), "z"),
            it("Redo", Selector(("redo:")), "z", [.command, .shift]),
            .separator(),
            it("Cut", #selector(NSText.cut(_:)), "x"),
            it("Copy", #selector(NSText.copy(_:)), "c"),
            it("Paste", #selector(NSText.paste(_:)), "v"),
            it("Select All", #selector(NSText.selectAll(_:)), "a"),
        ])
        let reload = it("Reload", #selector(reloadPage), "r")
        reload.target = self
        sub("View", [reload])
        sub("Window", [
            it("Minimize", #selector(NSWindow.performMiniaturize(_:)), "m"),
            it("Close", #selector(NSWindow.performClose(_:)), "w"),
        ])
        NSApp.mainMenu = main
    }

    @objc func reloadPage() {
        if web.url == nil { signIn() } else { web.reload() }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
