import Foundation

struct JobDefinition {
    let name: String
    let run: String
    let schedule: String?
    let cwd: String
}

@MainActor
final class Jobs {
    var log: (String) -> Void = { _ in }
    private var running: Set<String> = []
    private let home = FileManager.default.homeDirectoryForCurrentUser.path

    private var stateDirectory: String { "\(home)/.loops" }

    private var watcherPlist: [String: Any] {
        let path = "\(home)/Library/LaunchAgents/dev.coey.loops.plist"
        guard let data = FileManager.default.contents(atPath: path),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return [:] }
        return plist
    }

    var watcherDirectory: String { watcherPlist["WorkingDirectory"] as? String ?? home }

    var loopsFile: String? {
        var directory = URL(fileURLWithPath: watcherDirectory)
        while true {
            let candidate = directory.appendingPathComponent("loops.yaml").path
            if FileManager.default.fileExists(atPath: candidate) { return candidate }
            let parent = directory.deletingLastPathComponent()
            if parent.path == directory.path { return nil }
            directory = parent
        }
    }

    var loopsBinary: String? {
        let arguments = watcherPlist["ProgramArguments"] as? [String] ?? []
        return arguments.first { $0.hasSuffix("/loops") } ?? ["\(home)/.bun/bin/loops", "/opt/homebrew/bin/loops"].first { FileManager.default.fileExists(atPath: $0) }
    }

    var watcherAlive: Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-f", "loops watch"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    private static func alive(_ pid: Any?) -> Bool {
        guard let pid = (pid as? NSNumber)?.int32Value, pid > 0 else { return false }
        return kill(pid, 0) == 0
    }

    func definitions() -> [JobDefinition] {
        guard let path = loopsFile, let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        let base = (path as NSString).deletingLastPathComponent
        return Jobs.parse(text).map { name, fields in
            let cwd = fields["cwd"].map { ($0 as NSString).isAbsolutePath ? $0 : ((base as NSString).appendingPathComponent($0) as NSString).standardizingPath } ?? base
            return JobDefinition(name: name, run: fields["run"] ?? "", schedule: fields["schedule"], cwd: cwd)
        }
    }

    static func parse(_ text: String) -> [(String, [String: String])] {
        var loops: [(String, [String: String])] = []
        var inLoops = false
        for raw in text.components(separatedBy: "\n") {
            let line = raw.replacingOccurrences(of: "\t", with: "  ")
            let content = stripComment(line.trimmingCharacters(in: .whitespaces))
            if content.isEmpty { continue }
            let indent = line.prefix { $0 == " " }.count
            if indent == 0 {
                inLoops = content.hasPrefix("loops:")
                continue
            }
            guard inLoops else { continue }
            if indent == 2, content.hasSuffix(":") {
                loops.append((String(content.dropLast()).trimmingCharacters(in: .whitespaces), [:]))
                continue
            }
            if indent >= 4, !loops.isEmpty, let colon = content.firstIndex(of: ":") {
                let key = content[..<colon].trimmingCharacters(in: .whitespaces)
                let value = unquote(content[content.index(after: colon)...].trimmingCharacters(in: .whitespaces))
                loops[loops.count - 1].1[key] = value
            }
        }
        return loops
    }

    private static func stripComment(_ text: String) -> String {
        var single = false
        var double = false
        var previous: Character = " "
        for (offset, character) in text.enumerated() {
            if character == "'" && !double { single.toggle() }
            else if character == "\"" && !single { double.toggle() }
            else if character == "#" && !single && !double && previous == " " {
                return String(text.prefix(offset)).trimmingCharacters(in: .whitespaces)
            }
            previous = character
        }
        return text
    }

    private static func unquote(_ text: String) -> String {
        guard text.count >= 2, let first = text.first, first == text.last, first == "\"" || first == "'" else { return text }
        return String(text.dropFirst().dropLast())
    }

    private func latest(_ name: String) -> [String: Any] {
        guard let data = FileManager.default.contents(atPath: "\(stateDirectory)/\(name)/latest.json"),
              let record = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return record
    }

    private func recentExits(_ name: String, limit: Int) -> [Int] {
        let directory = "\(stateDirectory)/\(name)"
        let logs = ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).filter { $0.hasSuffix(".log") }.sorted().suffix(limit)
        return logs.compactMap { file in
            guard let handle = FileHandle(forReadingAtPath: "\(directory)/\(file)") else { return nil }
            defer { try? handle.close() }
            let size = (try? handle.seekToEnd()) ?? 0
            try? handle.seek(toOffset: size > 64 ? size - 64 : 0)
            let tail = String(decoding: handle.readDataToEndOfFile(), as: UTF8.self)
            guard let range = tail.range(of: "# exit: ", options: .backwards) else { return nil }
            return Int(tail[range.upperBound...].prefix { $0.isNumber || $0 == "-" })
        }
    }

    func list() -> [String: Any] {
        let defined = definitions()
        let definedNames = Set(defined.map(\.name))
        let stateNames = ((try? FileManager.default.contentsOfDirectory(atPath: stateDirectory)) ?? []).filter { name in
            var isDirectory: ObjCBool = false
            return FileManager.default.fileExists(atPath: "\(stateDirectory)/\(name)", isDirectory: &isDirectory) && isDirectory.boolValue && name != "watchers"
        }
        let entry: (String, JobDefinition?) -> [String: Any] = { name, definition in
            var row: [String: Any] = [
                "name": name,
                "defined": definition != nil,
                "run": definition?.run ?? "",
                "schedule": definition?.schedule ?? "",
                "cwd": definition?.cwd ?? "",
                "running": self.running.contains(name),
                "recent": self.recentExits(name, limit: 10),
            ]
            let record = self.latest(name)
            for key in ["startedAt", "finishedAt", "exitCode", "logPath"] { if let value = record[key] { row[key] = value } }
            let unfinished = record["startedAt"] != nil && record["finishedAt"] == nil
            row["running"] = self.running.contains(name) || (unfinished && Jobs.alive(record["pid"]))
            row["abandoned"] = unfinished && !(row["running"] as? Bool ?? false)
            return row
        }
        let jobs = defined.map { entry($0.name, $0) } + stateNames.filter { !definedNames.contains($0) }.sorted().map { entry($0, nil) }
        return [
            "file": loopsFile ?? "",
            "watcher": watcherAlive,
            "jobs": jobs,
        ]
    }

    func tail(_ name: String, lines: Int) -> String {
        guard Jobs.safeName(name) else { return "" }
        let path = latest(name)["logPath"] as? String
            ?? ((try? FileManager.default.contentsOfDirectory(atPath: "\(stateDirectory)/\(name)")) ?? []).filter { $0.hasSuffix(".log") }.sorted().last.map { "\(stateDirectory)/\(name)/\($0)" }
        guard let path, let text = try? String(contentsOfFile: path, encoding: .utf8) else { return "No runs yet." }
        return text.components(separatedBy: "\n").suffix(lines).joined(separator: "\n")
    }

    static func safeName(_ name: String) -> Bool {
        !name.isEmpty && name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "." } && !name.hasPrefix(".")
    }

    func run(_ name: String, done: @escaping @MainActor @Sendable () -> Void) -> String? {
        guard Jobs.safeName(name), definitions().contains(where: { $0.name == name }) else { return "No job named \(name) in loops.yaml" }
        guard let binary = loopsBinary, let file = loopsFile else { return "loops CLI or loops.yaml not found" }
        guard !running.contains(name) else { return "\(name) is already running" }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["run", name]
        process.currentDirectoryURL = URL(fileURLWithPath: (file as NSString).deletingLastPathComponent)
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "\(home)/.bun/bin:/opt/homebrew/bin:/usr/local/bin:" + (environment["PATH"] ?? "/usr/bin:/bin")
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] finished in
            let status = finished.terminationStatus
            Task { @MainActor in
                self?.running.remove(name)
                self?.log("job \(name) finished exit=\(status)")
                done()
            }
        }
        do {
            try process.run()
        } catch {
            return "Could not start \(name): \(error.localizedDescription)"
        }
        running.insert(name)
        log("job \(name) started")
        return nil
    }
}
