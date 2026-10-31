import * as Option from 'effect/Option';
import * as Schema from 'effect/Schema';
import { type DrawShape, ServerFrameJson } from '../../shared/protocol';

type ShellEvent =
  | { type: 'hold'; mode: 'dictate' | 'agent' }
  | { type: 'release'; mode: 'dictate' | 'agent' }
  | { type: 'transcript'; mode: 'dictate' | 'agent'; text: string; screen: { width: number; height: number } }
  | { type: 'level'; value: number }
  | { type: 'speaking'; value: boolean }
  | { type: 'settings'; value: Settings }
  | { type: 'escape' };

type Phase = 'idle' | 'listening' | 'thinking' | 'speaking';

export type McpServer = { name: string; transport: 'http' | 'stdio'; target: string; enabledInPi: boolean; enabledInT2T: boolean };
export type Settings = {
  speak: boolean;
  voice: string;
  mcp: McpServer[];
  mcpPath: string;
  permissions: { inputMonitoring: boolean; accessibility: boolean; screenRecording: boolean; keys: boolean };
};
export type TranscriptLine = { at: number; mode: 'dictate' | 'agent'; role: 'you' | 'agent' | 'error'; text: string };

declare global {
  interface Window {
    t2t?: { receive: (event: ShellEvent) => void };
    webkit?: { messageHandlers?: { t2t?: { postMessage: (body: unknown) => void } } };
  }
}

const decodeFrame = Schema.decodeUnknownOption(ServerFrameJson);

const params = new URLSearchParams(location.search);
const agentBase = params.get('agent') ?? import.meta.env.VITE_T2T_AGENT ?? 'wss://t2t-v2.customer0.dev';
const agentKey = params.get('key') ?? import.meta.env.VITE_T2T_KEY ?? '';

export const overlay = $state({
  phase: 'idle' as Phase,
  mode: 'dictate' as 'dictate' | 'agent',
  shapes: [] as DrawShape[],
  reply: '',
  connected: false,
  turnId: '',
  lastError: '',
  level: 0,
  talking: false,
  settings: undefined as Settings | undefined,
  transcript: [] as TranscriptLine[],
});

const transcriptKey = 't2t.transcript';
export const loadTranscript = (): TranscriptLine[] => {
  try {
    return JSON.parse(localStorage.getItem(transcriptKey) ?? '[]');
  } catch {
    return [];
  }
};
const remember = (line: Omit<TranscriptLine, 'at'>) => {
  const next = [{ ...line, at: Date.now() }, ...loadTranscript()].slice(0, 500);
  localStorage.setItem(transcriptKey, JSON.stringify(next));
  overlay.transcript = next;
};

export const shell = (body: Record<string, unknown>) => window.webkit?.messageHandlers?.t2t?.postMessage(body);

let socket: WebSocket | undefined;
let retryMs = 250;
const pending: string[] = [];

const send = (frame: Record<string, unknown>) => {
  const encoded = JSON.stringify(frame);
  if (socket?.readyState === WebSocket.OPEN) socket.send(encoded);
  else pending.push(encoded);
};

const connect = () => {
  socket = new WebSocket(`${agentBase}/agent?key=${encodeURIComponent(agentKey)}`);
  socket.onopen = () => {
    overlay.connected = true;
    retryMs = 250;
    while (pending.length > 0) socket?.send(pending.shift() ?? '');
  };
  socket.onclose = () => {
    overlay.connected = false;
    setTimeout(connect, retryMs);
    retryMs = Math.min(retryMs * 2, 8000);
  };
  socket.onmessage = (event) => {
    const frame = decodeFrame(event.data);
    if (Option.isNone(frame)) return;
    const value = frame.value;
    if (value.turnId !== overlay.turnId && value.turnId !== 'none') return;
    if (value.type === 'text') {
      overlay.phase = 'speaking';
      overlay.reply += value.text;
    }
    if (value.type === 'draw') overlay.shapes = [...overlay.shapes, value.shape];
    if (value.type === 'clear') overlay.shapes = [];
    if (value.type === 'done') {
      overlay.reply = value.reply;
      overlay.phase = 'idle';
      remember({ mode: 'agent', role: 'agent', text: value.reply });
      shell({ command: 'speak', text: value.reply });
    }
    if (value.type === 'failed') {
      overlay.lastError = `${value.step}: ${value.reason}`;
      overlay.phase = 'idle';
      remember({ mode: 'agent', role: 'error', text: overlay.lastError });
    }
  };
};

const sendTurn = (text: string, screen: { width: number; height: number }) => {
  const turnId = crypto.randomUUID();
  overlay.turnId = turnId;
  overlay.reply = '';
  overlay.lastError = '';
  overlay.phase = 'thinking';
  send({ type: 'turn', turnId, text, screen });
};

const receive = (event: ShellEvent) => {
  if (event.type === 'level') {
    const attack = event.value > overlay.level ? 0.6 : 0.25;
    overlay.level += (event.value - overlay.level) * attack;
    return;
  }
  if (event.type === 'speaking') {
    overlay.talking = event.value;
    return;
  }
  if (event.type === 'settings') {
    overlay.settings = event.value;
    return;
  }
  if (event.type === 'hold') {
    overlay.mode = event.mode;
    overlay.phase = 'listening';
  }
  if (event.type === 'release') overlay.level = 0;
  if (event.type === 'release') overlay.phase = event.mode === 'agent' ? 'thinking' : 'idle';
  if (event.type === 'transcript') {
    if (event.text.trim() === '') {
      overlay.phase = 'idle';
      return;
    }
    remember({ mode: event.mode, role: 'you', text: event.text });
    if (event.mode === 'dictate') {
      overlay.phase = 'idle';
      shell({ command: 'paste', text: event.text });
    } else sendTurn(event.text, event.screen);
  }
  if (event.type === 'escape') dismiss();
};

export const dismiss = () => {
  if (overlay.phase === 'thinking' && overlay.turnId !== '') send({ type: 'cancel', turnId: overlay.turnId });
  shell({ command: 'stopSpeaking' });
  overlay.shapes = [];
  overlay.reply = '';
  overlay.lastError = '';
  overlay.phase = 'idle';
};

export const setSetting = (key: string, value: unknown) => shell({ command: 'set', key, value });

window.t2t = { receive };
shell({ command: 'settings' });
if (!location.pathname.startsWith('/settings')) connect();
