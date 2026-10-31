import AVFoundation
import Speech

@MainActor
final class Dictation {
    private let engine = AVAudioEngine()
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private var latest = ""
    private var finish: ((String) -> Void)?
    private let recognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US"))


    func start() throws {
        latest = ""
        let request = SFSpeechAudioBufferRecognitionRequest()
        request.shouldReportPartialResults = true
        if recognizer?.supportsOnDeviceRecognition == true { request.requiresOnDeviceRecognition = true }
        self.request = request
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        input.removeTap(onBus: 0)
        input.installTap(onBus: 0, bufferSize: 1024, format: format, block: makeAppender(request))
        engine.prepare()
        try engine.start()
        task = recognizer?.recognitionTask(with: request) { @Sendable [weak self] result, error in
            let text = result?.bestTranscription.formattedString
            let final = result?.isFinal == true || error != nil
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self else { return }
                    if let text { self.latest = text }
                    if final, let finish = self.finish {
                        self.finish = nil
                        finish(self.latest)
                    }
                }
            }
        }
    }

    func stop(_ done: @escaping (String) -> Void) {
        finish = done
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        request?.endAudio()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            MainActor.assumeIsolated {
                guard let self, let finish = self.finish else { return }
                self.finish = nil
                self.task?.cancel()
                finish(self.latest)
            }
        }
    }
}

nonisolated func requestSpeechAndMicAccess(_ done: @escaping @Sendable (Bool) -> Void) {
    SFSpeechRecognizer.requestAuthorization { @Sendable status in
        AVCaptureDevice.requestAccess(for: .audio) { @Sendable mic in
            done(status == .authorized && mic)
        }
    }
}

nonisolated func makeAppender(_ request: SFSpeechAudioBufferRecognitionRequest) -> AVAudioNodeTapBlock {
    { buffer, _ in request.append(buffer) }
}
