import Foundation

@MainActor
final class McpHost {
    private var process: Process?
    var log: (String) -> Void = { _ in }

    private var script: URL? {
        if let env = ProcessInfo.processInfo.environment["T2T_MCP_HOST"] { return URL(fileURLWithPath: env) }
        if let saved = UserDefaults.standard.string(forKey: "mcpHostScript") { return URL(fileURLWithPath: saved) }
        return nil
    }

    func start(key: String) {
        stop()
        guard let script else {
            log("mcp host: no script configured (defaults key mcpHostScript)")
            return
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-lc", "exec node \"$T2T_MCP_SCRIPT\""]
        var environment = ProcessInfo.processInfo.environment
        environment["T2T_MCP_SCRIPT"] = script.path
        environment["T2T_KEY"] = key
        process.environment = environment
        process.currentDirectoryURL = script.deletingLastPathComponent().deletingLastPathComponent()
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let text = String(decoding: handle.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { return }
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.log("mcp host: \(text.prefix(400))") } }
        }
        process.terminationHandler = { [weak self] finished in
            let status = finished.terminationStatus
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.process === finished else { return }
                    self.log("mcp host exited \(status), restarting in 1s")
                    self.process = nil
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                        MainActor.assumeIsolated { if self.process == nil { self.start(key: key) } }
                    }
                }
            }
        }
        do {
            try process.run()
            self.process = process
        } catch {
            log("mcp host failed to start: \(error)")
        }
    }

    func stop() {
        guard let process else { return }
        self.process = nil
        if process.isRunning { process.terminate() }
    }
}
