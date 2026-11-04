import AppKit
import WebKit

@MainActor
final class Bridge: NSObject, WKScriptMessageHandler {
    weak var overlay: WKWebView?
    weak var settings: WKWebView?
    var onPaste: (String) -> Void = { _ in }
    var onSpeak: (String) -> Void = { _ in }
    var onSpeakChunk: (String) -> Void = { _ in }
    var onStopSpeaking: () -> Void = {}
    var onHitRegions: ([[String: Double]]) -> Void = { _ in }
    var onOpenSettings: () -> Void = {}
    var onWindow: ([String: Any]) -> Void = { _ in }
    var onWindowClose: (String) -> Void = { _ in }
    var onWindowRecord: (String, Double, String) -> Void = { _, _, _ in }
    var onWindows: ([[String: Any]]) -> Void = { _ in }
    var settingsState: () -> [String: Any] = { [:] }
    var onSetting: (String, Any) -> Void = { _, _ in }
    var jobsState: () -> [String: Any] = { [:] }
    var onJobRun: (String) -> String? = { _ in nil }
    var jobLog: (String, Int) -> String = { _, _ in "" }
    var log: (String) -> Void = { _ in }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any], let command = body["command"] as? String else { return }
        switch command {
        case "paste":
            if let text = body["text"] as? String { onPaste(text) }
        case "speak":
            if let text = body["text"] as? String { onSpeak(text) }
        case "speakChunk":
            if let text = body["text"] as? String { onSpeakChunk(text) }
        case "stopSpeaking":
            onStopSpeaking()
        case "hitRegions":
            onHitRegions((body["rects"] as? [[String: Double]]) ?? [])
        case "window":
            if let window = body["window"] as? [String: Any] { onWindow(window) }
        case "windowRecord":
            if let id = body["id"] as? String, let path = body["path"] as? String {
                onWindowRecord(id, body["seconds"] as? Double ?? 8, path)
            }
        case "windowClose":
            if let id = body["id"] as? String { onWindowClose(id) }
        case "windows":
            onWindows((body["windows"] as? [[String: Any]]) ?? [])
        case "openSettings":
            onOpenSettings()
        case "settings":
            send(["type": "settings", "value": settingsState()], to: message.webView)
        case "set":
            if let key = body["key"] as? String, let value = body["value"] {
                onSetting(key, value)
                broadcastSettings()
            }
        case "jobs":
            send(["type": "jobs", "value": jobsState()], to: message.webView)
        case "jobRun":
            if let name = body["name"] as? String {
                let error = onJobRun(name)
                send(["type": "jobRun", "name": name, "error": error ?? ""], to: message.webView)
                send(["type": "jobs", "value": jobsState()], to: message.webView)
            }
        case "jobLog":
            if let name = body["name"] as? String {
                send(["type": "jobLog", "name": name, "text": jobLog(name, body["lines"] as? Int ?? 80)], to: message.webView)
            }
        case "log":
            if let line = body["line"] as? String { log("ui: \(line)") }
        default:
            log("unknown bridge command \(command)")
        }
    }

    func broadcastSettings() {
        let event: [String: Any] = ["type": "settings", "value": settingsState()]
        send(event, to: overlay)
        send(event, to: settings)
    }

    func emit(_ event: [String: Any]) {
        send(event, to: overlay)
        send(event, to: settings)
    }

    private func send(_ event: [String: Any], to view: WKWebView?) {
        guard let view,
              let data = try? JSONSerialization.data(withJSONObject: event),
              let json = String(data: data, encoding: .utf8) else { return }
        view.evaluateJavaScript("window.t2t && window.t2t.receive(\(json))", completionHandler: nil)
    }
}
