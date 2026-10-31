import Foundation

@MainActor
final class GatewayToken {
    private var timer: Timer?
    private var key = ""
    private var agentBase = URL(string: "https://t2t-v2.customer0.dev")!
    var log: (String) -> Void = { _ in }
    var onStatus: ([String: Any]) -> Void = { _ in }
    private(set) var status: [String: Any] = ["state": "unknown"]

    private let app = "<access app from defaults gatewayAccessApp>"
    private let refreshEvery: TimeInterval = 6 * 3600
    private let renewBelowHours = 72

    func start(key: String, agentBase: URL) {
        self.key = key
        self.agentBase = agentBase
        refresh(interactive: false)
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: refreshEvery, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh(interactive: false) }
        }
    }

    func refresh(interactive: Bool) {
        let app = self.app
        let key = self.key
        let endpoint = agentBase.appendingPathComponent("agent/gateway-token")
        setStatus(["state": "refreshing"])
        Task {
            let minted = await Task.detached { mintToken(app: app, interactive: interactive) }.value
            guard let token = minted.token else {
                setStatus(["state": "login-needed", "error": minted.error])
                log("gateway token: \(minted.error)")
                return
            }
            if !interactive, let hours = hoursUntilExpiry(token), hours < renewBelowHours {
                log("gateway token has \(hours)h left; renewing with cloudflared access login")
                refresh(interactive: true)
                return
            }
            let pushed = await pushToken(token, to: endpoint, key: key)
            if let hoursLeft = pushed.hoursLeft {
                setStatus(["state": "ok", "hoursLeft": hoursLeft])
                log("gateway token pushed; agent has \(hoursLeft)h left")
            } else {
                setStatus(["state": "push-failed", "error": pushed.error])
                log("gateway token push failed: \(pushed.error)")
            }
        }
    }

    private func setStatus(_ value: [String: Any]) {
        status = value
        onStatus(value)
    }
}

struct MintedToken: Sendable {
    let token: String?
    let error: String
}

nonisolated func mintToken(app: String, interactive: Bool) -> MintedToken {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    let command = interactive ? "cloudflared access login \"$APP\" >/dev/null 2>&1; cloudflared access token -app \"$APP\"" : "cloudflared access token -app \"$APP\""
    process.arguments = ["-lc", command]
    var environment = ProcessInfo.processInfo.environment
    environment["APP"] = app
    process.environment = environment
    let out = Pipe()
    let err = Pipe()
    process.standardOutput = out
    process.standardError = err
    do { try process.run() } catch { return MintedToken(token: nil, error: "cloudflared did not start: \(error)") }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    let failure = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    let token = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    guard process.terminationStatus == 0, token.split(separator: ".").count == 3 else {
        return MintedToken(token: nil, error: "Access login needed for \(app): \(failure.suffix(200))")
    }
    return MintedToken(token: token, error: "")
}

struct PushResult: Sendable {
    let hoursLeft: Int?
    let error: String
}

nonisolated func pushToken(_ token: String, to endpoint: URL, key: String) async -> PushResult {
    var request = URLRequest(url: endpoint)
    request.httpMethod = "PUT"
    request.setValue("Bearer \(key)", forHTTPHeaderField: "authorization")
    request.httpBody = Data(token.utf8)
    do {
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard status == 200, let hours = body?["hoursLeft"] as? Int else {
            return PushResult(hoursLeft: nil, error: "HTTP \(status) \(String(decoding: data.prefix(200), as: UTF8.self))")
        }
        return PushResult(hoursLeft: hours, error: "")
    } catch {
        return PushResult(hoursLeft: nil, error: "\(error)")
    }
}

nonisolated func hoursUntilExpiry(_ token: String) -> Int? {
    let parts = token.split(separator: ".")
    guard parts.count == 3 else { return nil }
    var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
    guard let data = Data(base64Encoded: payload),
          let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let exp = claims["exp"] as? Double else { return nil }
    return Int((exp - Date().timeIntervalSince1970) / 3600)
}
