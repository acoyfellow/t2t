import AppKit
import ApplicationServices
import CoreGraphics

@MainActor
final class App: NSObject, NSApplicationDelegate {
    private var status: NSStatusItem?
    private let bridge = Bridge()
    private var overlay: Overlay?
    private let keys = Keys()
    private let dictation = Dictation()
    private let control = Control()
    private var lastTranscript = ""
    private var lastPasted = ""
    private var forcedTranscript: String?
    private var keysListening = false
    private let logURL: URL = {
        let env = ProcessInfo.processInfo.environment["T2T_LOG"]
        let saved = UserDefaults.standard.string(forKey: "logPath")
        let path = env ?? saved ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/t2t-v2.log").path
        return URL(fileURLWithPath: path)
    }()

    private var uiURL: URL {
        let env = ProcessInfo.processInfo.environment["T2T_UI_URL"]
        let saved = UserDefaults.standard.string(forKey: "uiURL")
        return URL(string: env ?? saved ?? "http://127.0.0.1:5197/")!
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = App.menuBarMark()
        let menu = NSMenu()
        menu.addItem(withTitle: "Reload UI", action: #selector(reloadUI), keyEquivalent: "r")
        menu.addItem(withTitle: "Open log", action: #selector(openLog), keyEquivalent: "l")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit t2t", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = menu
        status = item

        bridge.log = { [weak self] line in self?.log(line) }
        bridge.onPaste = { [weak self] text in
            self?.lastPasted = text
            Paste.type(text)
        }
        let overlay = Overlay(bridge: bridge)
        overlay.load(uiURL)
        self.overlay = overlay

        keys.onStart = { [weak self] mode in self?.holdStarted(mode) }
        keys.onStop = { [weak self] mode in self?.holdStopped(mode) }
        keys.onEscape = { [weak self] in self?.bridge.emit(["type": "escape"]) }
        keys.onRaw = { [weak self] line in self?.log(line) }
        dictation.log = { [weak self] line in self?.log(line) }
        dictation.onLevel = { [weak self] level in self?.bridge.emit(["type": "level", "value": level]) }
        let inputMonitoring = Keys.inputMonitoringGranted(prompt: true)
        log("input monitoring granted=\(inputMonitoring)")
        keysListening = keys.start()
        log("started; keys listening=\(keysListening) accessibility=\(Paste.trusted(prompt: false)) ui=\(redacted(uiURL))")
        if !Paste.trusted(prompt: false) { _ = Paste.trusted(prompt: true) }
        requestSpeechAndMicAccess { granted in
            Task { @MainActor in self.log("speech+mic granted=\(granted)") }
        }

        control.handle = { [weak self] path, query in self?.route(path, query) ?? "{}" }
        control.start(port: 5198)
    }

    private func holdStarted(_ mode: HoldMode) {
        log("hold start \(mode.rawValue)")
        bridge.emit(["type": "hold", "mode": mode.rawValue])
        if forcedTranscript != nil { return }
        do { try dictation.start() } catch { log("dictation start failed: \(error)") }
    }

    private func holdStopped(_ mode: HoldMode) {
        bridge.emit(["type": "release", "mode": mode.rawValue])
        let deliver: (String) -> Void = { [weak self] text in
            guard let self else { return }
            self.lastTranscript = text
            self.log("transcript (\(mode.rawValue)): \(text)")
            let screen = NSScreen.main?.frame.size ?? .zero
            self.bridge.emit([
                "type": "transcript", "mode": mode.rawValue, "text": text,
                "screen": ["width": screen.width, "height": screen.height],
            ])
        }
        if let forced = forcedTranscript {
            forcedTranscript = nil
            deliver(forced)
            return
        }
        dictation.stop(deliver)
    }

    private func route(_ path: String, _ query: [String: String]) -> String {
        switch path {
        case "/state":
            let payload: [String: Any] = [
                "keys": keysListening,
                "inputMonitoring": Keys.inputMonitoringGranted(prompt: false),
                "accessibility": Paste.trusted(prompt: false),
                "screenRecording": CGPreflightScreenCaptureAccess(),
                "lastTranscript": lastTranscript,
                "lastPasted": lastPasted,
                "ui": redacted(uiURL),
                "overlayLevel": overlay?.window.level.rawValue ?? 0,
                "overlayVisible": overlay?.window.isVisible ?? false,
            ]
            return json(payload)
        case "/hold":
            let mode = HoldMode(rawValue: query["mode"] ?? "dictate") ?? .dictate
            forcedTranscript = query["text"]
            keys.simulate(mode, seconds: Double(query["seconds"] ?? "0.4") ?? 0.4)
            return json(["ok": true])
        case "/reload":
            reloadUI()
            return json(["ok": true])
        default:
            return json(["error": "unknown path \(path)"])
        }
    }

    private func redacted(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return "" }
        components.queryItems = components.queryItems?.map { URLQueryItem(name: $0.name, value: $0.name == "key" ? "redacted" : $0.value) }
        return components.string ?? ""
    }

    private func json(_ value: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    static func menuBarMark() -> NSImage? {
        guard let url = Bundle.main.url(forResource: "mark", withExtension: "svg"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.size = NSSize(width: 16, height: 16)
        image.isTemplate = true
        return image
    }

    @objc private func reloadUI() {
        overlay?.load(uiURL)
    }

    @objc private func openLog() {
        NSWorkspace.shared.open(logURL)
    }

    private func log(_ line: String) {
        let stamped = "[\(ISO8601DateFormatter().string(from: Date()))] \(line)\n"
        if let handle = try? FileHandle(forWritingTo: logURL) {
            handle.seekToEndOfFile()
            handle.write(stamped.data(using: .utf8)!)
            try? handle.close()
        } else {
            try? stamped.data(using: .utf8)?.write(to: logURL)
        }
    }
}
