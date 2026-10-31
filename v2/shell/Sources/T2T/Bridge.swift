import AppKit
import WebKit

@MainActor
final class Bridge: NSObject, WKScriptMessageHandler {
    weak var overlay: WKWebView?
    var onPaste: (String) -> Void = { _ in }
    var log: (String) -> Void = { _ in }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any], let command = body["command"] as? String else { return }
        switch command {
        case "paste":
            if let text = body["text"] as? String { onPaste(text) }
        case "log":
            if let line = body["line"] as? String { log("ui: \(line)") }
        default:
            log("unknown bridge command \(command)")
        }
    }

    func emit(_ event: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: event),
              let json = String(data: data, encoding: .utf8) else { return }
        overlay?.evaluateJavaScript("window.t2t && window.t2t.receive(\(json))", completionHandler: nil)
    }
}
