import AppKit
import WebKit

@MainActor
final class Overlay: NSObject, WKNavigationDelegate {
    let window: NSWindow
    let webView: WKWebView

    init(bridge: Bridge) {
        let controller = WKUserContentController()
        controller.add(bridge, name: "t2t")
        let configuration = WKWebViewConfiguration()
        configuration.userContentController = controller
        configuration.websiteDataStore = .default()
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.setValue(false, forKey: "drawsBackground")
        if #available(macOS 13.3, *) { webView.isInspectable = true }

        let frame = Overlay.coveredFrame()
        window = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: false)
        super.init()
        webView.navigationDelegate = self
        window.contentView = webView
        window.isOpaque = false
        window.backgroundColor = .clear
        window.hasShadow = false
        window.ignoresMouseEvents = true
        window.level = .screenSaver
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        window.isReleasedWhenClosed = false
        window.setFrame(frame, display: true)
        window.orderFrontRegardless()
        bridge.overlay = webView

        NotificationCenter.default.addObserver(
            forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.window.setFrame(Overlay.coveredFrame(), display: true) }
        }
    }

    static func coveredFrame() -> NSRect {
        NSScreen.main?.frame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
    }

    func load(_ url: URL) {
        webView.load(URLRequest(url: url))
    }

    func send(_ json: String) {
        webView.evaluateJavaScript("window.t2t && window.t2t.receive(\(json))", completionHandler: nil)
    }
}
