export {};

declare global {
  interface Window {
    __startRecording?: () => void | Promise<void>;
    __stopRecording?: () => void | Promise<void>;
    __setProcessing?: (v: boolean) => void;
    __setLevel?: (v: number) => void;
  }
}


