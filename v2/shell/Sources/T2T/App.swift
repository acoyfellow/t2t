import AppKit
import ApplicationServices
import CoreGraphics

@MainActor
final class App: NSObject, NSApplicationDelegate {
    private var status: NSStatusItem?
    private let bridge = Bridge()
    private let jobs = Jobs()
    private var overlay: Overlay?
    private let keys = Keys()
    private let dictation = Dictation()
    private let control = Control()
    private let speaker = Speaker()
    private let mcpHost = McpHost()
    private let outputMute = OutputMute()
    private let gateway = GatewayToken()
    private let agentWindows = AgentWindows()
    private var hits: HitRegions?
    private lazy var settingsWindow = SettingsWindow(bridge: bridge)
    private var lastTranscript = ""
    private var lastPasted = ""
    private var forcedTranscript: String?
    private var query_streamPieces: [String] = []
    private var keysListening = false
    private var holdMode: HoldMode = .dictate
    private var streamedPaste = false
    private var segmentTimes: [Date] = []
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
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.image = App.menuBarMark()
        let menu = NSMenu()
        menu.addItem(withTitle: "Settings…", action: #selector(openSettings), keyEquivalent: ",")
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
        bridge.onSpeak = { [weak self] text in self?.speaker.speak(text) }
        bridge.onSpeakChunk = { [weak self] text in self?.speaker.enqueue(text) }
        bridge.onStopSpeaking = { [weak self] in self?.speaker.stop() }
        speaker.onStart = { [weak self] in self?.bridge.emit(["type": "speaking", "value": true]) }
        speaker.onFinish = { [weak self] in self?.bridge.emit(["type": "speaking", "value": false]) }
        speaker.log = { [weak self] line in self?.log(line) }
        bridge.onOpenSettings = { [weak self] in self?.openSettings() }
        bridge.onWindow = { [weak self] entry in
            guard let id = entry["id"] as? String else { return }
            self?.agentWindows.show(
                id: id,
                title: entry["title"] as? String ?? id,
                html: entry["html"] as? String ?? "",
                width: entry["width"] as? Double ?? 640,
                height: entry["height"] as? Double ?? 480
            )
        }
        bridge.onWindowClose = { [weak self] id in self?.agentWindows.close(id: id) }
        bridge.onWindowRecord = { [weak self] id, seconds, path in self?.agentWindows.record(id: id, seconds: seconds, path: path) }
        bridge.onWindows = { [weak self] entries in self?.agentWindows.sync(entries) }
        agentWindows.log = { [weak self] line in self?.log(line) }
        agentWindows.onUserClosed = { [weak self] id in self?.bridge.emit(["type": "windowClosed", "id": id]) }
        bridge.settingsState = { [weak self] in self?.settingsState() ?? [:] }
        bridge.onSetting = { [weak self] key, value in self?.applySetting(key, value) }
        jobs.log = { [weak self] line in self?.log(line) }
        bridge.jobsState = { [weak self] in self?.jobs.list() ?? [:] }
        bridge.jobLog = { [weak self] name, lines in self?.jobs.tail(name, lines: lines) ?? "" }
        bridge.onJobRun = { [weak self] name in
            self?.jobs.run(name) { [weak self] in
                guard let self else { return }
                self.bridge.emit(["type": "jobs", "value": self.jobs.list()])
            }
        }
        let overlay = Overlay(bridge: bridge)
        overlay.load(uiURL)
        self.overlay = overlay
        let hits = HitRegions(window: overlay.window)
        bridge.onHitRegions = { rects in hits.set(rects) }
        self.hits = hits

        keys.onStart = { [weak self] mode in self?.holdStarted(mode) }
        keys.onStop = { [weak self] mode in self?.holdStopped(mode) }
        keys.onEscape = { [weak self] in
            self?.speaker.stop()
            self?.bridge.emit(["type": "escape"])
        }
        keys.onRaw = { [weak self] line in self?.log(line) }
        dictation.log = { [weak self] line in self?.log(line) }
        dictation.onSegment = { [weak self] piece in self?.segmentReady(piece) }
        dictation.onLevel = { [weak self] level in self?.bridge.emit(["type": "level", "value": level]) }
        let inputMonitoring = Keys.inputMonitoringGranted(prompt: true)
        log("input monitoring granted=\(inputMonitoring)")
        keysListening = keys.start()
        log("started; keys listening=\(keysListening) accessibility=\(Paste.trusted(prompt: false)) ui=\(redacted(uiURL))")
        if !Paste.trusted(prompt: false) { _ = Paste.trusted(prompt: true) }
        requestSpeechAndMicAccess { granted in
            Task { @MainActor in self.log("speech+mic granted=\(granted)") }
        }

        mcpHost.log = { [weak self] line in self?.log(line) }
        if let key = URLComponents(url: uiURL, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "key" })?.value {
            mcpHost.start(key: key)
            gateway.log = { [weak self] line in self?.log(line) }
            gateway.onStatus = { [weak self] _ in self?.bridge.broadcastSettings() }
            gateway.start(key: key, agentBase: URL(string: UserDefaults.standard.string(forKey: "agentURL") ?? "https://t2t-v2.customer0.dev")!)
        }

        control.handle = { [weak self] path, query in self?.route(path, query) ?? "{}" }
        control.start(port: 5198)
    }

    func applicationWillTerminate(_ notification: Notification) {
        mcpHost.stop()
    }

    private var streamDictation: Bool { UserDefaults.standard.object(forKey: "streamDictation") as? Bool ?? true }

    private func segmentReady(_ piece: String) {
        segmentTimes.append(Date())
        bridge.emit(["type": "partial", "mode": holdMode.rawValue, "text": piece])
        guard holdMode == .dictate, streamDictation else { return }
        streamedPaste = true
        lastPasted += piece
        Paste.type(piece)
    }

    private func holdStarted(_ mode: HoldMode) {
        holdMode = mode
        streamedPaste = false
        lastPasted = ""
        log("hold start \(mode.rawValue)")
        speaker.stop()
        outputMute.begin()
        bridge.emit(["type": "hold", "mode": mode.rawValue])
        if forcedTranscript != nil { return }
        do { try dictation.start() } catch { log("dictation start failed: \(error)") }
    }

    private func holdStopped(_ mode: HoldMode) {
        outputMute.end()
        bridge.emit(["type": "release", "mode": mode.rawValue])
        let deliver: (String) -> Void = { [weak self] text in
            guard let self else { return }
            self.lastTranscript = text
            self.log("transcript (\(mode.rawValue)): \(text)")
            let screen = NSScreen.main?.frame.size ?? .zero
            self.bridge.emit([
                "type": "transcript", "mode": mode.rawValue, "text": text, "streamed": self.streamedPaste,
                "screen": ["width": screen.width, "height": screen.height],
            ])
        }
        if let forced = forcedTranscript {
            forcedTranscript = nil
            if mode == .dictate, streamDictation, query_streamPieces.isEmpty == false {
                for piece in query_streamPieces { segmentReady(piece) }
                query_streamPieces = []
                deliver(lastPasted)
                return
            }
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
                "segments": segmentTimes.count,
                "ui": redacted(uiURL),
                "overlayLevel": overlay?.window.level.rawValue ?? 0,
                "overlayVisible": overlay?.window.isVisible ?? false,
                "gateway": gateway.status,
                "statusItem": [
                    "frame": NSStringFromRect(status?.button?.window?.frame ?? .zero),
                    "visible": status?.isVisible ?? false,
                    "hasImage": status?.button?.image != nil,
                ],
            ]
            return json(payload)
        case "/hold":
            let mode = HoldMode(rawValue: query["mode"] ?? "dictate") ?? .dictate
            forcedTranscript = query["text"]
            query_streamPieces = (query["pieces"] ?? "").split(separator: "|").map { String($0) }.enumerated().map { $0.offset == 0 ? $0.element : " " + $0.element }
            keys.simulate(mode, seconds: Double(query["seconds"] ?? "0.4") ?? 0.4)
            return json(["ok": true])
        case "/windows":
            let open = agentWindows.openIds.map { id -> [String: Any] in
                let frame = agentWindows.frame(of: id) ?? .zero
                return ["id": id, "frame": [frame.origin.x, frame.origin.y, frame.width, frame.height]]
            }
            return json(["windows": open])
        case "/window-eval":
            guard let id = query["id"] else { return json(["error": "id required"]) }
            if let script = query["js"] { agentWindows.evaluate(id: id, script: script) }
            return json(["result": agentWindows.evalResults[id] ?? ""])
        case "/window-open":
            guard let id = query["id"], let file = query["file"], let html = try? String(contentsOfFile: file, encoding: .utf8) else { return json(["error": "id and readable file required"]) }
            agentWindows.show(id: id, title: query["title"] ?? id, html: html, width: Double(query["width"] ?? "1200") ?? 1200, height: Double(query["height"] ?? "760") ?? 760)
            return json(["ok": true])
        case "/window-record":
            guard let id = query["id"] else { return json(["error": "id required"]) }
            if let path = query["path"] {
                agentWindows.record(id: id, seconds: Double(query["seconds"] ?? "6") ?? 6, path: path)
            }
            return json(["status": agentWindows.lastRecording[id] ?? "none"])
        case "/window-close":
            guard let id = query["id"] else { return json(["error": "id required"]) }
            agentWindows.closeAsUser(id: id)
            return json(["ok": true])
        case "/confirm":
            bridge.emit(["type": "confirmAnswer", "callId": query["callId"] ?? "", "allow": query["allow"] == "1"])
            return json(["ok": true])
        case "/set":
            guard let key = query["key"], let raw = query["value"] else { return json(["error": "key and value required"]) }
            let value: Any = raw == "true" ? true as Any : raw == "false" ? false as Any : raw as Any
            applySetting(key, value)
            bridge.broadcastSettings()
            return json(["ok": true])
        case "/settings-open":
            openSettingsSection(query["section"])
            return json(["ok": true])
        case "/replay":
            guard let path = query["file"] else { return json(["error": "file required"]) }
            holdMode = .dictate
            streamedPaste = false
            lastPasted = ""
            segmentTimes = []
            let started = Date()
            dictation.replay(URL(fileURLWithPath: path)) { [weak self] text in
                guard let self else { return }
                self.lastTranscript = text
                self.log("replay transcript: \(text) segments=\(self.segmentTimes.map { String(format: "%.1f", $0.timeIntervalSince(started)) })")
            }
            return json(["ok": true])
        case "/jobs":
            return json(jobs.list())
        case "/job-log":
            return json(["text": jobs.tail(query["name"] ?? "", lines: Int(query["lines"] ?? "40") ?? 40)])
        case "/job-run":
            let error = jobs.run(query["name"] ?? "") { [weak self] in
                guard let self else { return }
                self.bridge.emit(["type": "jobs", "value": self.jobs.list()])
            }
            return json(error.map { ["error": $0] } ?? ["ok": true])
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
        guard let url = Bundle.main.url(forResource: "logo", withExtension: "svg"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.size = NSSize(width: 26, height: 14)
        image.isTemplate = true
        return image
    }

    private func settingsState() -> [String: Any] {
        [
            "speak": speaker.enabled,
            "streamDictation": streamDictation,
            "pastePauseSeconds": dictation.pauseSeconds,
            "muteWhileTalking": outputMute.enabled,
            "confirmMcp": UserDefaults.standard.bool(forKey: "confirmMcp"),
            "voice": speaker.voice ?? "",
            "mcp": McpConfig.servers(),
            "mcpPath": McpConfig.path.path,
            "gateway": gateway.status,
            "permissions": [
                "inputMonitoring": Keys.inputMonitoringGranted(prompt: false),
                "accessibility": Paste.trusted(prompt: false),
                "screenRecording": CGPreflightScreenCaptureAccess(),
                "keys": keysListening,
            ],
        ]
    }

    private func applySetting(_ key: String, _ value: Any) {
        switch key {
        case "speak":
            speaker.enabled = value as? Bool ?? true
            if !speaker.enabled { speaker.stop() }
        case "confirmMcp":
            UserDefaults.standard.set(value as? Bool ?? false, forKey: "confirmMcp")
        case "muteWhileTalking":
            outputMute.enabled = value as? Bool ?? true
            if !outputMute.enabled { outputMute.end() }
        case "pastePauseSeconds":
            let seconds = (value as? Double) ?? Double(value as? String ?? "") ?? 0.55
            UserDefaults.standard.set(min(max(seconds, 0.2), 3.0), forKey: "pastePauseSeconds")
        case "streamDictation":
            UserDefaults.standard.set(value as? Bool ?? true, forKey: "streamDictation")
        case "refreshGateway":
            gateway.refresh(interactive: value as? Bool ?? false)
        case "voice":
            let voice = (value as? String).flatMap { $0.isEmpty ? nil : $0 }
            speaker.voice = voice
            UserDefaults.standard.set(voice, forKey: "voice")
        case "mcp":
            if let entry = value as? [String: Any], let name = entry["name"] as? String, let enabled = entry["enabled"] as? Bool {
                McpConfig.setEnabled(name, enabled)
            }
        default:
            log("unknown setting \(key)")
        }
    }

    @objc private func openSettings() {
        openSettingsSection(nil)
    }

    private func openSettingsSection(_ section: String?) {
        var components = URLComponents(url: uiURL, resolvingAgainstBaseURL: false)
        components?.path = "/settings.html"
        if let section {
            let kept = (components?.queryItems ?? []).filter { $0.name != "section" }
            components?.queryItems = kept + [URLQueryItem(name: "section", value: section)]
        }
        guard let url = components?.url else { return }
        settingsWindow.show(url, reload: section != nil)
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
