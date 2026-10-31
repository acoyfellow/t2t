import AppKit
import WebKit

@MainActor
final class SettingsWindow: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private let bridge: Bridge

    init(bridge: Bridge) {
        self.bridge = bridge
    }

    func show(_ url: URL) {
        if let window {
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let controller = WKUserContentController()
        controller.add(bridge, name: "t2t")
        let configuration = WKWebViewConfiguration()
        configuration.userContentController = controller
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        if #available(macOS 13.3, *) { webView.isInspectable = true }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 640),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered, defer: false
        )
        window.title = "t2t"
        window.contentView = webView
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()
        webView.load(URLRequest(url: url))
        bridge.settings = webView
        self.window = window
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        window = nil
        bridge.settings = nil
        NSApp.setActivationPolicy(.accessory)
    }
}
