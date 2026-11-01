import Foundation

enum McpConfig {
    static var path: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".pi/agent/mcp.json")
    }

    static var localPath: URL? {
        guard let script = UserDefaults.standard.string(forKey: "mcpHostScript") else { return nil }
        return URL(fileURLWithPath: script).deletingLastPathComponent().appendingPathComponent("mcp.local.json")
    }

    private static func read(_ url: URL?) -> [String: Any] {
        guard let url, let data = try? Data(contentsOf: url),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return root["mcpServers"] as? [String: Any] ?? [:]
    }

    static func servers() -> [[String: Any]] {
        let servers = read(path).merging(read(localPath)) { _, local in local }
        let enabledForT2T = Set(UserDefaults.standard.stringArray(forKey: "mcpEnabled") ?? [])
        return servers.keys.sorted().compactMap { name in
            guard let definition = servers[name] as? [String: Any] else { return nil }
            let url = definition["url"] as? String
            let command = definition["command"] as? String
            let args = (definition["args"] as? [String]) ?? []
            return [
                "name": name,
                "transport": url != nil ? "http" : "stdio",
                "target": url ?? ([command ?? ""] + args).joined(separator: " "),
                "enabledInPi": definition["enabled"] as? Bool ?? true,
                "enabledInT2T": enabledForT2T.contains(name),
            ]
        }
    }

    static func setEnabled(_ name: String, _ enabled: Bool) {
        var names = Set(UserDefaults.standard.stringArray(forKey: "mcpEnabled") ?? [])
        if enabled { names.insert(name) } else { names.remove(name) }
        UserDefaults.standard.set(names.sorted(), forKey: "mcpEnabled")
    }
}
