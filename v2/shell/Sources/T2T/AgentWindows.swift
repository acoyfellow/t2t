import AppKit
import WebKit

@MainActor
final class AgentWindows: NSObject, NSWindowDelegate {
    private var windows: [String: NSWindow] = [:]
    private var sources: [String: String] = [:]
    private var closingByAgent: Set<String> = []
    var onUserClosed: (String) -> Void = { _ in }
    var log: (String) -> Void = { _ in }

    var openIds: [String] { windows.keys.sorted() }

    func show(id: String, title: String, html: String, width: Double, height: Double) {
        sources[id] = html
        if let window = windows[id], let webView = window.contentView as? WKWebView {
            window.title = title
            webView.loadHTMLString(html, baseURL: URL(string: "https://t2t.local/"))
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
        window.level = .normal
        window.collectionBehavior = [.managed]
        window.delegate = self
        window.setFrameAutosaveName("t2t-window-\(id)")
        if !window.setFrameUsingName("t2t-window-\(id)") { window.center() }
        webView.loadHTMLString(html, baseURL: URL(string: "https://t2t.local/"))
        windows[id] = window
        window.orderFront(nil)
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

    private(set) var lastRecording: [String: String] = [:]

    private var recorders: [String: OffscreenRecorder] = [:]

    func record(id: String, seconds: Double, path: String) {
        guard let webView = windows[id]?.contentView as? WKWebView else {
            log("record \(id): no window")
            return
        }
        let size = webView.bounds.size
        let output = (path as NSString).expandingTildeInPath
        lastRecording[id] = "recording"
        log("record \(id): \(Int(seconds))s offscreen \(Int(size.width))x\(Int(size.height)) → \(output)")
        guard let html = sources[id] else { return }
        let recorder = OffscreenRecorder(html: html, size: size, seconds: seconds, output: output) { [weak self] result in
            self?.lastRecording[id] = result
            self?.recorders[id] = nil
            self?.log("record \(id): \(result)")
        }
        recorder.trace = { [weak self] line in self?.log("record \(id): \(line)") }
        recorders[id] = recorder
        recorder.start()
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

nonisolated private func run(_ path: String, _ arguments: [String]) -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return -1 }
    process.waitUntilExit()
    return process.terminationStatus
}
