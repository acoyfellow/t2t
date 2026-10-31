import AVFoundation
import Foundation

@MainActor
final class Dictation {
    private let engine = AVAudioEngine()
    private let meter = AudioMeter()
    private let recorder = PCMRecorder()
    var log: (String) -> Void = { _ in }
    var onLevel: (Double) -> Void = { _ in }
    var onSegment: (String) -> Void = { _ in }
    private var levelTimer: Timer?
    private var segmentTimer: Timer?
    private var cut = 0
    private var heardSpeech = false
    private var noiseFloor: Float = 0.01
    private var pending: Task<Void, Never>?
    private var pieces: [String] = []
    private var session = 0

    private let pauseSeconds = 0.55
    private let minimumSegmentSeconds = 1.2
    private let maximumSegmentSeconds = 12.0

    private let whisper = ProcessInfo.processInfo.environment["T2T_WHISPER"] ?? "/opt/homebrew/bin/whisper-cli"
    private let model = ProcessInfo.processInfo.environment["T2T_WHISPER_MODEL"]
        ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".cache/whisper/ggml-base.en.bin").path

    func start() throws {
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        session += 1
        meter.reset()
        recorder.reset(sourceRate: format.sampleRate)
        cut = 0
        heardSpeech = false
        noiseFloor = 0.01
        pieces = []
        pending = nil
        input.removeTap(onBus: 0)
        input.installTap(onBus: 0, bufferSize: 1024, format: format, block: makeTap(meter, recorder))
        engine.prepare()
        try engine.start()
        log("dictation start: \(format.sampleRate)Hz/\(format.channelCount)ch")
        levelTimer?.invalidate()
        levelTimer = Timer.scheduledTimer(withTimeInterval: 1.0 / 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.onLevel(normalizedLevel(self.meter.current))
            }
        }
        segmentTimer?.invalidate()
        segmentTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.checkForPause() }
        }
    }

    private func checkForPause() {
        let rate = recorder.rate
        let total = recorder.count
        let window = Int(rate * 0.1)
        guard total - cut > window else { return }
        let recent = recorder.rms(from: total - window, to: total)
        noiseFloor = min(max(noiseFloor * 0.995 + recent * 0.005, 0.002), max(recent, 0.002))
        let speechThreshold = max(noiseFloor * 3, 0.006)
        if recent > speechThreshold { heardSpeech = true }
        let length = Double(total - cut) / rate
        let pauseWindow = Int(rate * pauseSeconds)
        let quiet = total - cut > pauseWindow && recorder.rms(from: total - pauseWindow, to: total) < max(noiseFloor * 2, 0.004)
        if heardSpeech && length >= minimumSegmentSeconds && quiet {
            emit(upTo: total, final: false)
        } else if length >= maximumSegmentSeconds {
            emit(upTo: total, final: false)
        }
    }

    private func emit(upTo end: Int, final: Bool) {
        let start = cut
        cut = end
        let spoke = heardSpeech
        heardSpeech = false
        let samples = recorder.slice16k(from: start, to: end)
        guard spoke || final, samples.count > 16000 / 4 else { return }
        let whisper = self.whisper
        let model = self.model
        let previous = pending
        let current = session
        pending = Task {
            await previous?.value
            let started = Date()
            let text = await Task.detached { transcribeSamples(samples, whisper: whisper, model: model) }.value
            guard current == self.session else { return }
            self.log("segment \(String(format: "%.1f", Double(samples.count) / 16000))s → \(String(format: "%.2f", Date().timeIntervalSince(started)))s exit=\(text.status) \(text.error.prefix(120))")
            let cleaned = cleanSegment(text.text)
            guard !cleaned.isEmpty else { return }
            self.pieces.append(cleaned)
            self.onSegment(self.pieces.count == 1 ? cleaned : " " + cleaned)
        }
    }

    func replay(_ file: URL, done: @escaping (String) -> Void) {
        guard let audio = try? AVAudioFile(forReading: file),
              let buffer = AVAudioPCMBuffer(pcmFormat: audio.processingFormat, frameCapacity: AVAudioFrameCount(audio.length)),
              (try? audio.read(into: buffer)) != nil,
              let channel = buffer.floatChannelData?[0] else {
            log("replay: cannot read \(file.path)")
            return done("")
        }
        session += 1
        recorder.reset(sourceRate: audio.processingFormat.sampleRate)
        cut = 0
        heardSpeech = false
        noiseFloor = 0.01
        pieces = []
        pending = nil
        let all = Array(UnsafeBufferPointer(start: channel, count: Int(buffer.frameLength)))
        let step = Int(audio.processingFormat.sampleRate * 0.1)
        Task {
            var offset = 0
            while offset < all.count {
                recorder.appendSamples(Array(all[offset..<min(all.count, offset + step)]))
                offset += step
                checkForPause()
                try? await Task.sleep(for: .milliseconds(100))
            }
            emit(upTo: recorder.count, final: true)
            await pending?.value
            done(pieces.joined(separator: " "))
        }
    }

    func stop(_ done: @escaping (String) -> Void) {
        levelTimer?.invalidate()
        levelTimer = nil
        segmentTimer?.invalidate()
        segmentTimer = nil
        onLevel(0)
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        log("dictation stop: buffers=\(meter.buffers) peak=\(String(format: "%.4f", meter.peak)) seconds=\(String(format: "%.2f", Double(recorder.count) / recorder.rate))")
        emit(upTo: recorder.count, final: true)
        let last = pending
        Task {
            await last?.value
            done(self.pieces.joined(separator: " "))
        }
    }
}

nonisolated func cleanSegment(_ text: String) -> String {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    let noise: Set<String> = ["", "you", "you.", "thank you.", "thanks for watching!", "(silence)", "[silence]", "[blank_audio]"]
    return noise.contains(trimmed.lowercased()) ? "" : trimmed
}

nonisolated func transcribeSamples(_ samples: [Float], whisper: String, model: String) -> WhisperResult {
    let wav = FileManager.default.temporaryDirectory.appendingPathComponent("t2t-\(UUID().uuidString).wav")
    do { try writeWav(samples, to: wav) } catch {
        return WhisperResult(text: "", status: -1, error: "wav write failed: \(error)")
    }
    defer { try? FileManager.default.removeItem(at: wav) }
    return transcribe(whisper: whisper, model: model, wav: wav)
}

nonisolated func requestSpeechAndMicAccess(_ done: @escaping @Sendable (Bool) -> Void) {
    AVCaptureDevice.requestAccess(for: .audio) { @Sendable mic in done(mic) }
}

struct WhisperResult: Sendable {
    let text: String
    let status: Int32
    let error: String
}

nonisolated func transcribe(whisper: String, model: String, wav: URL) -> WhisperResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: whisper)
    process.arguments = ["-m", model, "-f", wav.path, "-nt", "-np", "-l", "en"]
    let out = Pipe()
    let err = Pipe()
    process.standardOutput = out
    process.standardError = err
    do { try process.run() } catch {
        return WhisperResult(text: "", status: -1, error: "\(error)")
    }
    let output = out.fileHandleForReading.readDataToEndOfFile()
    let failure = err.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let text = String(decoding: output, as: UTF8.self)
        .split(separator: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty && !$0.hasPrefix("[") }
        .joined(separator: " ")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let errorText = process.terminationStatus == 0 ? "" : String(decoding: failure.suffix(400), as: UTF8.self)
    return WhisperResult(text: text, status: process.terminationStatus, error: errorText)
}

nonisolated func writeWav(_ samples: [Float], to url: URL) throws {
    var data = Data()
    let rate: UInt32 = 16000
    let byteCount = UInt32(samples.count * 2)
    func append<T: FixedWidthInteger>(_ value: T) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
    data.append(contentsOf: Array("RIFF".utf8)); append(UInt32(36) + byteCount)
    data.append(contentsOf: Array("WAVEfmt ".utf8)); append(UInt32(16)); append(UInt16(1)); append(UInt16(1))
    append(rate); append(rate * 2); append(UInt16(2)); append(UInt16(16))
    data.append(contentsOf: Array("data".utf8)); append(byteCount)
    for sample in samples { append(Int16(max(-1, min(1, sample)) * Float(Int16.max))) }
    try data.write(to: url)
}

final class PCMRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var samples: [Float] = []
    private var sourceRate: Double = 48000

    func reset(sourceRate: Double) {
        lock.withLock {
            samples = []
            self.sourceRate = sourceRate
        }
    }

    var rate: Double { lock.withLock { sourceRate } }
    var count: Int { lock.withLock { samples.count } }

    func rms(from start: Int, to end: Int) -> Float {
        lock.withLock {
            let lower = max(0, start)
            let upper = min(samples.count, end)
            guard upper > lower else { return 0 }
            var energy: Float = 0
            for index in lower..<upper { energy += samples[index] * samples[index] }
            return (energy / Float(upper - lower)).squareRoot()
        }
    }

    func slice16k(from start: Int, to end: Int) -> [Float] {
        let (source, rate) = lock.withLock { () -> ([Float], Double) in
            let lower = max(0, start)
            let upper = min(samples.count, end)
            return (upper > lower ? Array(samples[lower..<upper]) : [], sourceRate)
        }
        return downsample(source, from: rate)
    }

    func appendSamples(_ chunk: [Float]) {
        lock.withLock { samples.append(contentsOf: chunk) }
    }

    func append(_ buffer: AVAudioPCMBuffer) {
        guard let channel = buffer.floatChannelData?[0] else { return }
        let chunk = Array(UnsafeBufferPointer(start: channel, count: Int(buffer.frameLength)))
        lock.withLock { samples.append(contentsOf: chunk) }
    }

    func drain16k() -> [Float] {
        let (source, rate) = lock.withLock { (samples, sourceRate) }
        return downsample(source, from: rate)
    }
}

nonisolated func downsample(_ source: [Float], from rate: Double) -> [Float] {
        let ratio = rate / 16000
        guard ratio > 0, !source.isEmpty else { return [] }
        let count = Int(Double(source.count) / ratio)
        var output = [Float](repeating: 0, count: count)
        for index in 0..<count {
            let start = Int(Double(index) * ratio)
            let end = min(source.count, max(start + 1, Int(Double(index + 1) * ratio)))
            var sum: Float = 0
            for position in start..<end { sum += source[position] }
            output[index] = sum / Float(end - start)
        }
        return output
}

final class AudioMeter: @unchecked Sendable {
    private let lock = NSLock()
    private var bufferCount = 0
    private var peakLevel: Float = 0
    private var latestLevel: Float = 0
    var current: Float { lock.withLock { latestLevel } }
    var buffers: Int { lock.withLock { bufferCount } }
    var peak: Float { lock.withLock { peakLevel } }
    func reset() { lock.withLock { bufferCount = 0; peakLevel = 0; latestLevel = 0 } }
    func record(_ buffer: AVAudioPCMBuffer) {
        var level: Float = 0
        var energy: Float = 0
        let frames = Int(buffer.frameLength)
        if let samples = buffer.floatChannelData?[0] {
            for index in 0..<frames {
                level = max(level, abs(samples[index]))
                energy += samples[index] * samples[index]
            }
        }
        let rms = frames > 0 ? (energy / Float(frames)).squareRoot() : 0
        lock.withLock { bufferCount += 1; peakLevel = max(peakLevel, level); latestLevel = rms }
    }
}

nonisolated func makeTap(_ meter: AudioMeter, _ recorder: PCMRecorder) -> AVAudioNodeTapBlock {
    { buffer, _ in
        meter.record(buffer)
        recorder.append(buffer)
    }
}

nonisolated func normalizedLevel(_ rms: Float) -> Double {
    guard rms > 0 else { return 0 }
    let decibels = 20 * log10(Double(rms))
    return min(1, max(0, (decibels + 55) / 45))
}
