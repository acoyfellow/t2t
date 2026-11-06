import AppKit

@MainActor
final class HitRegions {
    private var regions: [NSRect] = []
    private var timer: Timer?
    private weak var window: NSWindow?

    init(window: NSWindow) {
        self.window = window
        timer = Timer.scheduledTimer(withTimeInterval: 1.0 / 30, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.update() }
        }
    }

    func set(_ rects: [[String: Double]]) {
        regions = rects.compactMap { rect in
            guard let x = rect["x"], let y = rect["y"], let w = rect["w"], let h = rect["h"] else { return nil }
            return NSRect(x: x, y: y, width: w, height: h)
        }
        update()
    }

    private func update() {
        guard let window else { return }
        let mouse = NSEvent.mouseLocation
        let frame = window.frame
        let point = NSPoint(x: mouse.x - frame.minX, y: frame.maxY - mouse.y)
        let inside = regions.contains { $0.contains(point) }
        if window.ignoresMouseEvents == inside { window.ignoresMouseEvents = !inside }
    }
}
