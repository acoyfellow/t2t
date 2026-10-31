import Foundation

@MainActor
final class Speaker {
    private var process: Process?
    var onFinish: () -> Void = {}
    var voice: String? = UserDefaults.standard.string(forKey: "voice")
    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "speak") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "speak") }
    }

    func speak(_ text: String) {
        stop()
        guard enabled, !text.isEmpty else { return onFinish() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/say")
        process.arguments = (voice.map { ["-v", $0] } ?? []) + [text]
        process.terminationHandler = { [weak self] finished in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.process === finished else { return }
                    self.process = nil
                    self.onFinish()
                }
            }
        }
        do {
            try process.run()
            self.process = process
        } catch {
            onFinish()
        }
    }

    var speaking: Bool { process?.isRunning == true }

    func stop() {
        guard let process else { return }
        self.process = nil
        if process.isRunning { process.terminate() }
    }
}
