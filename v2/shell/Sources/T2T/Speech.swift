import Foundation

@MainActor
final class Speaker {
    private var process: Process?
    private var queue: [String] = []
    var onStart: () -> Void = {}
    var onFinish: () -> Void = {}
    var log: (String) -> Void = { _ in }
    var voice: String? = UserDefaults.standard.string(forKey: "voice")
    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "speak") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "speak") }
    }

    var speaking: Bool { process != nil || !queue.isEmpty }

    func speak(_ text: String) {
        stop()
        enqueue(text)
    }

    func enqueue(_ text: String) {
        let sentence = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard enabled, !sentence.isEmpty else { return }
        let wasIdle = !speaking
        queue.append(sentence)
        if wasIdle { onStart() }
        if process == nil { next() }
    }

    private func next() {
        guard !queue.isEmpty else {
            onFinish()
            return
        }
        let sentence = queue.removeFirst()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/say")
        process.arguments = (voice.map { ["-v", $0] } ?? []) + [sentence]
        process.terminationHandler = { [weak self] finished in
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.process === finished else { return }
                    self.process = nil
                    self.next()
                }
            }
        }
        do {
            try process.run()
            self.process = process
            log("say: \(sentence.prefix(80))")
        } catch {
            self.process = nil
            next()
        }
    }

    func stop() {
        queue.removeAll()
        guard let process else { return }
        self.process = nil
        if process.isRunning { process.terminate() }
        onFinish()
    }
}
