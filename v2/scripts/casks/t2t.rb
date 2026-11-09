cask "t2t" do
  version "2.0.0"
  sha256 :no_check

  url "https://github.com/acoyfellow/t2t/releases/download/v#{version}/t2t-v2.zip"
  name "t2t"
  desc "Push-to-talk dictation and a voice agent you configure, for macOS"
  homepage "https://github.com/acoyfellow/t2t"

  app "t2t-v2/T2T.app"

  preflight do
    system_command "/bin/bash", args: ["-c", "xattr -dr com.apple.quarantine '#{appdir}/T2T.app' 2>/dev/null || true"]
  end

  zap trash: [
    "~/Library/Application Support/dev.coey.t2t",
    "~/Library/Preferences/dev.coey.t2t.plist",
    "~/Library/LaunchAgents/dev.coey.t2t-ui.plist",
  ]

  caveats <<~EOS
    t2t is ad-hoc signed, not notarized. After install, run the bundle installer:
      ./scripts/install-bundle.sh
    Grant Microphone, Input Monitoring, Accessibility, and Screen Recording when asked.
  EOS
end
