import AppKit
import WebKit

@MainActor
final class OffscreenRecorder: NSObject, WKNavigationDelegate {
    private let html: String
    private let size: CGSize
    private let frameCount: Int
    private let output: String
    private let finished: (String) -> Void
    private let fps = 30
    private let scale: CGFloat = 2
    private let host: NSWindow
    private let webView: WKWebView
    private var encoder: Process?
    private var pipe: Pipe?
    private var captured = 0
    private var startedAt = Date()

    init(html: String, size: CGSize, seconds: Double, output: String, finished: @escaping (String) -> Void) {
        self.html = html
        self.size = size
        self.frameCount = max(1, Int(seconds * 30))
        self.output = output
        self.finished = finished
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        webView = WKWebView(frame: CGRect(origin: .zero, size: size), configuration: configuration)
        host = NSWindow(
            contentRect: CGRect(origin: CGPoint(x: -20000, y: -20000), size: size),
            styleMask: [.borderless], backing: .buffered, defer: false
        )
        super.init()
        host.isReleasedWhenClosed = false
        host.ignoresMouseEvents = true
        host.contentView = webView
        host.alphaValue = 0.01
        host.orderBack(nil)
        webView.navigationDelegate = self
    }

    func start() {
        try? FileManager.default.createDirectory(atPath: (output as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        guard let ffmpeg = ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return done("failed: ffmpeg not found")
        }
        let width = Int(size.width * scale) / 2 * 2
        let height = Int(size.height * scale) / 2 * 2
        let process = Process()
        process.executableURL = URL(fileURLWithPath: ffmpeg)
        process.arguments = [
            "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", "\(fps)", "-i", "-",
            "-vf", "scale=\(width):\(height)", "-c:v", "libx264", "-preset", "slow", "-crf", "16",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart", output,
        ]
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return done("failed: ffmpeg did not start") }
        encoder = process
        pipe = input
        webView.loadHTMLString(html, baseURL: URL(string: "https://t2t.local/"))
    }

    nonisolated func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        MainActor.assumeIsolated {
            startedAt = Date()
            captureNext()
        }
    }

    private func captureNext() {
        guard captured < frameCount else { return finish() }
        let wait = captured == 0 ? 1.2 : 0.0
        DispatchQueue.main.asyncAfter(deadline: .now() + wait) { [weak self] in
            MainActor.assumeIsolated { self?.snap() }
        }
    }

    private func snap() {
        let frameMs = 1000.0 / Double(fps)
        webView.evaluateJavaScript("typeof window.__kitTick === 'function' ? window.__kitTick(\(frameMs)) : -1") { [weak self] value, error in
            MainActor.assumeIsolated {
                guard let self else { return }
                if self.captured % 60 == 0 { self.trace("tick \(self.captured): \(value ?? "nil") \(error?.localizedDescription ?? "")") }
                self.capture()
            }
        }
    }

    private func capture() {
        let configuration = WKSnapshotConfiguration()
        configuration.afterScreenUpdates = true
        webView.takeSnapshot(with: configuration) { [weak self] image, _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                if let image, let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff),
                   let png = bitmap.representation(using: .png, properties: [:]) {
                    self.pipe?.fileHandleForWriting.write(png)
                }
                self.captured += 1
                self.captureNext()
            }
        }
    }

    private func finish() {
        pipe?.fileHandleForWriting.closeFile()
        let process = encoder
        let output = self.output
        Task.detached {
            process?.waitUntilExit()
            let status = process?.terminationStatus ?? -1
            await MainActor.run { [weak self] in
                self?.done(status == 0 ? "saved \(output)" : "failed: ffmpeg exit \(status)")
            }
        }
    }

    var trace: (String) -> Void = { _ in }

    private func done(_ result: String) {
        host.orderOut(nil)
        host.close()
        finished(result)
    }
}
