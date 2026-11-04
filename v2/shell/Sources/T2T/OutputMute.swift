import CoreAudio

@MainActor
final class OutputMute {
    private var mutedByUs: AudioDeviceID?

    var enabled: Bool {
        get { UserDefaults.standard.object(forKey: "muteWhileTalking") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "muteWhileTalking") }
    }

    func begin() {
        guard enabled, mutedByUs == nil, let device = defaultOutput(), muted(device) == false else { return }
        if setMuted(device, true) { mutedByUs = device }
    }

    func end() {
        guard let device = mutedByUs else { return }
        mutedByUs = nil
        _ = setMuted(device, false)
    }

    private func defaultOutput() -> AudioDeviceID? {
        var device = AudioDeviceID(0)
        var size = UInt32(MemoryLayout<AudioDeviceID>.size)
        var address = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDefaultOutputDevice,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        let status = AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &size, &device)
        return status == noErr && device != 0 ? device : nil
    }

    private func muteAddress() -> AudioObjectPropertyAddress {
        AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyMute, mScope: kAudioDevicePropertyScopeOutput, mElement: kAudioObjectPropertyElementMain)
    }

    private func muted(_ device: AudioDeviceID) -> Bool? {
        var address = muteAddress()
        var value = UInt32(0)
        var size = UInt32(MemoryLayout<UInt32>.size)
        guard AudioObjectGetPropertyData(device, &address, 0, nil, &size, &value) == noErr else { return nil }
        return value != 0
    }

    private func setMuted(_ device: AudioDeviceID, _ mute: Bool) -> Bool {
        var address = muteAddress()
        var value = UInt32(mute ? 1 : 0)
        return AudioObjectSetPropertyData(device, &address, 0, nil, UInt32(MemoryLayout<UInt32>.size), &value) == noErr
    }
}
