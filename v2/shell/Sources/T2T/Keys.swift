import AppKit
import CoreGraphics
import IOKit.hid

enum HoldMode: String {
    case dictate
    case agent
}

@MainActor
final class Keys {
    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private var holding: HoldMode?
    var onStart: (HoldMode) -> Void = { _ in }
    var onStop: (HoldMode) -> Void = { _ in }
    var onEscape: () -> Void = {}
    var onRaw: (String) -> Void = { _ in }

    static func inputMonitoringGranted(prompt: Bool) -> Bool {
        if IOHIDCheckAccess(kIOHIDRequestTypeListenEvent) == kIOHIDAccessTypeGranted { return true }
        if prompt { _ = IOHIDRequestAccess(kIOHIDRequestTypeListenEvent) }
        return false
    }

    func start() -> Bool {
        let mask = (1 << CGEventType.flagsChanged.rawValue) | (1 << CGEventType.keyDown.rawValue)
        let pointer = Unmanaged.passUnretained(self).toOpaque()
        guard let tap = CGEvent.tapCreate(
            tap: .cgSessionEventTap,
            place: .headInsertEventTap,
            options: .listenOnly,
            eventsOfInterest: CGEventMask(mask),
            callback: { _, type, event, pointer in
                guard let pointer else { return Unmanaged.passUnretained(event) }
                let keys = Unmanaged<Keys>.fromOpaque(pointer).takeUnretainedValue()
                let flags = event.flags
                let keyCode = event.getIntegerValueField(.keyboardEventKeycode)
                MainActor.assumeIsolated { keys.handle(type: type, flags: flags, keyCode: keyCode) }
                return Unmanaged.passUnretained(event)
            },
            userInfo: pointer
        ) else { return false }
        self.tap = tap
        let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
        self.source = source
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)
        return true
    }

    private func handle(type: CGEventType, flags: CGEventFlags, keyCode: Int64) {
        if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
            if let tap { CGEvent.tapEnable(tap: tap, enable: true) }
            return
        }
        if type == .keyDown && keyCode == 53 {
            onEscape()
            return
        }
        guard type == .flagsChanged else { return }
        let fn = flags.contains(.maskSecondaryFn)
        let control = flags.contains(.maskControl)
        onRaw("flags key=\(keyCode) fn=\(fn) ctrl=\(control)")
        if let mode = holding {
            if !fn {
                holding = nil
                onStop(mode)
            }
            return
        }
        if fn {
            let mode: HoldMode = control ? .agent : .dictate
            holding = mode
            onStart(mode)
        }
    }

    func simulate(_ mode: HoldMode, seconds: Double) {
        holding = mode
        onStart(mode)
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in
            MainActor.assumeIsolated {
                guard let self, self.holding == mode else { return }
                self.holding = nil
                self.onStop(mode)
            }
        }
    }
}
