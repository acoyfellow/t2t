import AppKit
import WebKit

@MainActor
final class AgentWindows: NSObject, NSWindowDelegate {
    private var windows: [String: NSWindow] = [:]
    private var closingByAgent: Set<String> = []
    var onUserClosed: (String) -> Void = { _ in }
    var log: (String) -> Void = { _ in }

    var openIds: [String] { windows.keys.sorted() }

    func show(id: String, title: String, html: String, width: Double, height: Double) {
        if let window = windows[id], let webView = window.contentView as? WKWebView {
            window.title = title
            webView.loadHTMLString(html, baseURL: URL(string: "https://t2t.local/"))
            window.orderFrontRegardless()
            log("window \(id) updated")
            return
        }
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        if #available(macOS 13.3, *) { webView.isInspectable = true }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: height),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered, defer: false
        )
        window.identifier = NSUserInterfaceItemIdentifier("t2t-window-\(id)")
        window.title = title
        window.contentView = webView
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.delegate = self
        window.setFrameAutosaveName("t2t-window-\(id)")
        if !window.setFrameUsingName("t2t-window-\(id)") { window.center() }
        webView.loadHTMLString(html, baseURL: URL(string: "https://t2t.local/"))
        windows[id] = window
        window.orderFrontRegardless()
        log("window \(id) opened")
    }

    func close(id: String) {
        guard let window = windows[id] else { return }
        closingByAgent.insert(id)
        window.close()
    }

    private(set) var evalResults: [String: String] = [:]

    func evaluate(id: String, script: String) {
        guard let webView = windows[id]?.contentView as? WKWebView else {
            evalResults[id] = "no window"
            return
        }
        webView.evaluateJavaScript(script) { [weak self] value, error in
            MainActor.assumeIsolated {
                self?.evalResults[id] = error.map { "error: \($0.localizedDescription)" } ?? String(describing: value ?? "nil")
            }
        }
    }

    func closeAsUser(id: String) {
        windows[id]?.performClose(nil)
    }

    func sync(_ entries: [[String: Any]]) {
        let wanted = Set(entries.compactMap { $0["id"] as? String })
        for id in openIds where !wanted.contains(id) { close(id: id) }
        for entry in entries {
            guard let id = entry["id"] as? String, windows[id] == nil else { continue }
            show(
                id: id,
                title: entry["title"] as? String ?? id,
                html: entry["html"] as? String ?? "",
                width: entry["width"] as? Double ?? 640,
                height: entry["height"] as? Double ?? 480
            )
        }
    }

    func frame(of id: String) -> CGRect? {
        windows[id]?.frame
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow,
              let id = windows.first(where: { $0.value === window })?.key else { return }
        windows[id] = nil
        if closingByAgent.remove(id) == nil {
            log("window \(id) closed by user")
            onUserClosed(id)
        } else {
            log("window \(id) closed by agent")
        }
    }
}
