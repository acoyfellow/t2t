import Foundation

enum FSM {
    static func holdNext(_ state: String, _ event: String) -> String? {
        switch (state, event) {
        case ("none", "START_DICTATE"): return "dictate"
        case ("none", "START_AGENT"): return "agent"
        case ("dictate", "START_AGENT"): return "agent"
        case ("agent", "START_DICTATE"): return "dictate"
        case ("dictate", "STOP"), ("dictate", "ESCAPE"): return "none"
        case ("agent", "STOP"), ("agent", "ESCAPE"): return "none"
        default: return nil
        }
    }

    static func gatewayNext(_ state: String, _ event: String) -> String? {
        switch (state, event) {
        case ("unknown", "REFRESH"), ("ok", "REFRESH"), ("login-needed", "REFRESH"), ("push-failed", "REFRESH"): return "refreshing"
        case ("refreshing", "OK"): return "ok"
        case ("refreshing", "NEED_LOGIN"): return "login-needed"
        case ("refreshing", "PUSH_FAILED"): return "push-failed"
        default: return nil
        }
    }

    static func jobNext(_ state: String, _ event: String) -> String? {
        switch (state, event) {
        case ("idle", "START"), ("abandoned", "START"): return "running"
        case ("running", "FINISH"): return "idle"
        case ("running", "LOST"): return "abandoned"
        default: return nil
        }
    }

    static func statsNext(_ state: String, _ event: String) -> String? {
        switch (state, event) {
        case ("not-imported", "IMPORT"), ("imported", "IMPORT"): return "imported"
        default: return nil
        }
    }
}
