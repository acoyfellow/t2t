import Foundation

@MainActor
final class Stats {
    var log: (String) -> Void = { _ in }
    private let file: URL
    private let legacyFile: URL
    private var values: [String: Any] = [:]

    init(directory: URL? = nil, legacy: URL? = nil) {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let home = directory ?? support.appendingPathComponent("dev.coey.t2t")
        file = home.appendingPathComponent("stats.json")
        legacyFile = legacy ?? support.appendingPathComponent("com.t2t.desktop/stats.json")
        load()
    }

    private func load() {
        if let data = try? Data(contentsOf: file), let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            values = parsed
            return
        }
        importLegacy()
    }

    @discardableResult
    func importLegacy() -> Bool {
        guard let data = try? Data(contentsOf: legacyFile),
              let legacy = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        guard (values["importedFrom"] as? String) == nil else { return false }
        for key in ["total_words", "total_seconds", "session_count", "session_wpm_sum"] {
            values[key] = number(key) + ((legacy[key] as? NSNumber)?.doubleValue ?? 0)
        }
        var hours = hourly()
        for pair in (legacy["activity_hourly"] as? [[Any]]) ?? [] {
            guard pair.count == 2, let hour = (pair[0] as? NSNumber)?.int64Value, let words = (pair[1] as? NSNumber)?.doubleValue else { continue }
            hours[hour, default: 0] += words
        }
        setHourly(hours)
        values["importedFrom"] = legacyFile.path
        values["importedAt"] = ISO8601DateFormatter().string(from: Date())
        save()
        log("stats imported from \(legacyFile.path)")
        return true
    }

    func record(text: String, seconds: Double) {
        let words = text.split(whereSeparator: \.isWhitespace).count
        guard words > 0 else { return }
        let wpm = seconds > 0 ? Double(words) / (seconds / 60) : 0
        values["total_words"] = number("total_words") + Double(words)
        values["total_seconds"] = number("total_seconds") + max(seconds, 0)
        values["session_count"] = number("session_count") + 1
        values["session_wpm_sum"] = number("session_wpm_sum") + wpm
        var hours = hourly()
        hours[Int64(Date().timeIntervalSince1970 / 3600), default: 0] += Double(words)
        setHourly(hours)
        save()
    }

    func summary() -> [String: Any] {
        let words = number("total_words")
        let seconds = number("total_seconds")
        let sessions = number("session_count")
        let nowHour = Int64(Date().timeIntervalSince1970 / 3600)
        let hours = hourly()
        let recent = (0..<48).map { hours[nowHour - 47 + Int64($0)] ?? 0 }
        var payload: [String: Any] = [
            "totalWords": words,
            "sessions": sessions,
            "hoursActive": seconds / 3600,
            "lifetimeWpm": seconds > 0 ? words / (seconds / 60) : 0,
            "sessionAvgWpm": sessions > 0 ? number("session_wpm_sum") / sessions : 0,
            "recent": recent,
            "legacyAvailable": FileManager.default.fileExists(atPath: legacyFile.path),
        ]
        if let from = values["importedFrom"] { payload["importedFrom"] = from }
        if let at = values["importedAt"] { payload["importedAt"] = at }
        return payload
    }

    private func number(_ key: String) -> Double { (values[key] as? NSNumber)?.doubleValue ?? 0 }

    private func hourly() -> [Int64: Double] {
        var hours: [Int64: Double] = [:]
        for pair in (values["activity_hourly"] as? [[Any]]) ?? [] {
            guard pair.count == 2, let hour = (pair[0] as? NSNumber)?.int64Value, let words = (pair[1] as? NSNumber)?.doubleValue else { continue }
            hours[hour, default: 0] += words
        }
        return hours
    }

    private func setHourly(_ hours: [Int64: Double]) {
        values["activity_hourly"] = hours.keys.sorted().map { [NSNumber(value: $0), NSNumber(value: hours[$0] ?? 0)] }
    }

    private func save() {
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
            try data.write(to: file, options: .atomic)
        } catch {
            log("stats save failed: \(error)")
        }
    }
}
