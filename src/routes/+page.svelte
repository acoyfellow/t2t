<script lang="ts">
  import { onMount } from "svelte";

  let recording = $state(false);
  let processing = $state(false);
  let mediaRecorder: MediaRecorder | null = null;
  let chunks: Blob[] = [];
  let stream: MediaStream | null = null;

  function createWavHeader(dataSize: number, sampleRate = 16000): ArrayBuffer {
    const header = new ArrayBuffer(44);
    const view = new DataView(header);
    const byteRate = sampleRate * 2;

    view.setUint32(0, 0x52494646, false); // "RIFF"
    view.setUint32(4, 36 + dataSize, true);
    view.setUint32(8, 0x57415645, false); // "WAVE"
    view.setUint32(12, 0x666d7420, false); // "fmt "
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true); // PCM
    view.setUint16(22, 1, true); // mono
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, byteRate, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    view.setUint32(36, 0x64617461, false); // "data"
    view.setUint32(40, dataSize, true);
    return header;
  }

  async function blobToWav(blob: Blob): Promise<Uint8Array> {
    const audioCtx = new AudioContext({ sampleRate: 16000 });
    const audioBuffer = await audioCtx.decodeAudioData(
      await blob.arrayBuffer()
    );
    audioCtx.close();

    const { numberOfChannels, length } = audioBuffer;
    const mono = new Float32Array(length);

    for (let i = 0; i < numberOfChannels; i++) {
      const channel = audioBuffer.getChannelData(i);
      for (let j = 0; j < length; j++) {
        mono[j] += channel[j] / numberOfChannels;
      }
    }

    const pcm = new Int16Array(length);
    for (let i = 0; i < length; i++) {
      pcm[i] = Math.max(-32768, Math.min(32767, mono[i] * 32768));
    }

    const dataSize = pcm.length * 2;
    const header = createWavHeader(dataSize);
    const wav = new Uint8Array(44 + dataSize);
    wav.set(new Uint8Array(header), 0);
    wav.set(new Uint8Array(pcm.buffer), 44);

    return wav;
  }

  onMount(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");

      const feLog = async (msg: string) => {
        try {
          await invoke("log_event", { message: msg });
        } catch {
          // ignore
        }
      };

      // UI only. Audio capture/transcription is native-side now.
      (window as any).__startRecording = async () => {
        if (recording) return;
        recording = true;
        await feLog("UI: startRecording");
      };

      (window as any).__stopRecording = () => {
        if (!recording) return;
        recording = false;
        feLog("UI: stopRecording");
      };

      (window as any).__setProcessing = (v: boolean) => {
        processing = v;
      };
      await feLog(
        "Frontend initialized (__startRecording/__stopRecording set)."
      );
    } catch (e) {
      console.error("Init error:", e);
    }
  });
</script>

<div class="orb" class:recording class:processing>
  <div class="inner"></div>
  <div class="ring"></div>
  {#if recording}
    <div class="pulse"></div>
    <div class="pulse delay"></div>
  {/if}
</div>

<style>
  :global(html, body) {
    margin: 0;
    padding: 0;
    background: transparent;
    overflow: hidden;
    pointer-events: none;
  }

  :global(*) {
    pointer-events: none;
  }

  .orb {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .inner {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: #4a4a4a;
    transition: all 0.2s ease;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  }

  .ring {
    position: absolute;
    inset: 4px;
    border-radius: 50%;
    border: 2px solid transparent;
    transition: all 0.2s ease;
  }

  .pulse {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 2px solid #ef4444;
    animation: pulse-out 1.5s ease-out infinite;
  }

  .pulse.delay {
    animation-delay: 0.75s;
  }

  /* Recording state */
  .orb.recording .inner {
    background: #ef4444;
    box-shadow:
      0 0 20px #ef4444,
      0 0 40px rgba(239, 68, 68, 0.5);
    animation: glow 1s ease-in-out infinite;
  }

  .orb.recording .ring {
    border-color: rgba(239, 68, 68, 0.4);
  }

  /* Processing state */
  .orb.processing .inner {
    background: #f59e0b;
    box-shadow: 0 0 15px #f59e0b;
    animation: spin-glow 0.8s linear infinite;
  }

  .orb.processing .ring {
    border-color: rgba(245, 158, 11, 0.4);
    animation: spin 1s linear infinite;
  }

  @keyframes glow {
    0%,
    100% {
      box-shadow:
        0 0 20px #ef4444,
        0 0 40px rgba(239, 68, 68, 0.5);
      transform: scale(1);
    }
    50% {
      box-shadow:
        0 0 30px #ef4444,
        0 0 60px rgba(239, 68, 68, 0.6);
      transform: scale(1.1);
    }
  }

  @keyframes pulse-out {
    0% {
      transform: scale(1);
      opacity: 0.8;
    }
    100% {
      transform: scale(2);
      opacity: 0;
    }
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  @keyframes spin-glow {
    0%,
    100% {
      box-shadow: 0 0 15px #f59e0b;
    }
    50% {
      box-shadow: 0 0 25px #f59e0b;
    }
  }
</style>
