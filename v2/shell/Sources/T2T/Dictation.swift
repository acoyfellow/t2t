import AVFoundation
import Foundation

@MainActor
final class Dictation {
    private let engine = AVAudioEngine()
    private let meter = AudioMeter()
    private let recorder = PCMRecorder()
    var log: (String) -> Void = { _ in }
    var onLevel: (Double) -> Void = { _ in }
    private var levelTimer: Timer?

    private let whisper = ProcessInfo.processInfo.environment["T2T_WHISPER"] ?? "/opt/homebrew/bin/whisper-cli"
    private let model = ProcessInfo.processInfo.environment["T2T_WHISPER_MODEL"]
        ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".cache/whisper/ggml-base.en.bin").path

    func start() throws {
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)
        meter.reset()
        recorder.reset(sourceRate: format.sampleRate)
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
    }

    func stop(_ done: @escaping (String) -> Void) {
        levelTimer?.invalidate()
        levelTimer = nil
        onLevel(0)
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        let samples = recorder.drain16k()
        log("dictation stop: buffers=\(meter.buffers) peak=\(String(format: "%.4f", meter.peak)) seconds=\(String(format: "%.2f", Double(samples.count) / 16000))")
        guard samples.count > 16000 / 4 else {
            done("")
            return
        }
        let wav = FileManager.default.temporaryDirectory.appendingPathComponent("t2t-\(UUID().uuidString).wav")
        do { try writeWav(samples, to: wav) } catch {
            log("wav write failed: \(error)")
            done("")
            return
        }
        let whisper = self.whisper
        let model = self.model
        let started = Date()
        Task {
            let result = await Task.detached { transcribe(whisper: whisper, model: model, wav: wav) }.value
            try? FileManager.default.removeItem(at: wav)
            log("whisper \(String(format: "%.2f", Date().timeIntervalSince(started)))s exit=\(result.status) \(result.error.prefix(200))")
            done(result.text)
        }
    }
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

    func append(_ buffer: AVAudioPCMBuffer) {
        guard let channel = buffer.floatChannelData?[0] else { return }
        let chunk = Array(UnsafeBufferPointer(start: channel, count: Int(buffer.frameLength)))
        lock.withLock { samples.append(contentsOf: chunk) }
    }

    func drain16k() -> [Float] {
        let (source, rate) = lock.withLock { (samples, sourceRate) }
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
