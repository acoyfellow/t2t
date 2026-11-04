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

    private var failures = 0

    func start(key: String) {
        stop()
        releaseOrphanedPort()
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
                    self.failures += 1
                    let delay = min(60.0, pow(2.0, Double(min(self.failures, 6) - 1)))
                    self.log("mcp host exited \(status), restarting in \(Int(delay))s")
                    self.process = nil
                    DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                        MainActor.assumeIsolated { if self.process == nil { self.start(key: key) } }
                    }
                }
            }
        }
        do {
            try process.run()
            self.process = process
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
                MainActor.assumeIsolated { if self?.process === process { self?.failures = 0 } }
            }
        } catch {
            log("mcp host failed to start: \(error)")
        }
    }

    func stop() {
        guard let process else { return }
        self.process = nil
        if process.isRunning { process.terminate() }
    }

    private func releaseOrphanedPort() {
        let finder = Process()
        finder.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        finder.arguments = ["-tiTCP:5196", "-sTCP:LISTEN"]
        let output = Pipe()
        finder.standardOutput = output
        finder.standardError = FileHandle.nullDevice
        guard (try? finder.run()) != nil else { return }
        finder.waitUntilExit()
        let text = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for pid in text.split(separator: "\n").compactMap({ pid_t($0) }) where isOrphanedHost(pid) {
            log("mcp host: stopping orphaned host pid \(pid) on port 5196")
            kill(pid, SIGTERM)
        }
    }

    private func isOrphanedHost(_ pid: pid_t) -> Bool {
        let inspector = Process()
        inspector.executableURL = URL(fileURLWithPath: "/bin/ps")
        inspector.arguments = ["-o", "ppid=,command=", "-p", String(pid)]
        let output = Pipe()
        inspector.standardOutput = output
        guard (try? inspector.run()) != nil else { return false }
        inspector.waitUntilExit()
        let line = (String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "").trimmingCharacters(in: .whitespaces)
        return line.hasPrefix("1 ") && line.contains("mcp-host.mjs")
    }
}
