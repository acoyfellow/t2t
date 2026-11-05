import * as Option from 'effect/Option';
import * as Schema from 'effect/Schema';
import { type DrawShape, ServerFrameJson } from '../../shared/protocol';
import { type ActionEvent, applyAction, hideIdle } from './cursors.svelte';

type ShellEvent =
  | { type: 'hold'; mode: 'dictate' | 'agent' }
  | { type: 'release'; mode: 'dictate' | 'agent' }
  | { type: 'transcript'; mode: 'dictate' | 'agent'; text: string; streamed?: boolean; screen: { width: number; height: number } }
  | { type: 'partial'; mode: 'dictate' | 'agent'; text: string }
  | { type: 'level'; value: number }
  | { type: 'speaking'; value: boolean }
  | { type: 'settings'; value: Settings }
  | { type: 'windowClosed'; id: string }
  | { type: 'section'; value: string }
  | { type: 'confirmAnswer'; callId: string; allow: boolean }
  | { type: 'stats'; value: StatsState }
  | { type: 'jobs'; value: JobsState }
  | { type: 'jobRun'; name: string; error: string }
  | { type: 'jobLog'; name: string; text: string }
  | { type: 'escape' };

export type Job = {
  name: string;
  defined: boolean;
  run: string;
  schedule: string;
  cwd: string;
  running: boolean;
  abandoned: boolean;
  recent: number[];
  startedAt?: string;
  finishedAt?: string;
  exitCode?: number;
};
export type StatsState = {
  totalWords: number;
  sessions: number;
  hoursActive: number;
  lifetimeWpm: number;
  sessionAvgWpm: number;
  recent: number[];
  legacyAvailable: boolean;
  importedFrom?: string;
  importedAt?: string;
};
export const stats = $state<{ value?: StatsState }>({});
export type JobsState = { file: string; watcher: boolean; jobs: Job[] };
export const jobs = $state<{ state?: JobsState; logs: Record<string, string>; error: string }>({ logs: {}, error: '' });

type Phase = 'idle' | 'listening' | 'thinking' | 'speaking';

export type McpServer = { name: string; transport: 'http' | 'stdio'; target: string; enabledInPi: boolean; enabledInT2T: boolean };
export type Settings = {
  speak: boolean;
  streamDictation: boolean;
  pastePauseSeconds: number;
  muteWhileTalking: boolean;
  confirmMcp: boolean;
  voice: string;
  mcp: McpServer[];
  mcpPath: string;
  gateway: { state: 'unknown' | 'refreshing' | 'ok' | 'login-needed' | 'push-failed'; hoursLeft?: number; error?: string; host?: string };
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
const mcpHost = params.get('mcp') ?? 'http://127.0.0.1:5196';

type McpToolEntry = { server: string; name: string; description: string; inputSchema: unknown };

const mcpPost = async <A>(path: string, body: unknown): Promise<A> => {
  const response = await fetch(`${mcpHost}${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${agentKey}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return response.json() as Promise<A>;
};

const enabledServers = () => overlay.settings?.mcp.filter((server) => server.enabledInT2T).map((server) => server.name) ?? [];

const localTools = async (): Promise<McpToolEntry[]> => {
  const names = enabledServers();
  if (names.length === 0) return [];
  try {
    const { servers } = await mcpPost<{ servers: { server: string; ok: boolean; error?: string; tools?: Omit<McpToolEntry, 'server'>[] }[] }>('/tools', { servers: names });
    for (const failed of servers.filter((entry) => !entry.ok)) shell({ command: 'log', line: `mcp ${failed.server} unavailable: ${failed.error}` });
    return servers.flatMap((entry) => (entry.tools ?? []).map((tool) => ({ ...tool, server: entry.server })));
  } catch (error) {
    shell({ command: 'log', line: `mcp host unreachable: ${error}` });
    return [];
  }
};

let actionSeq = -1;
const pollActions = async () => {
  try {
    const response = await fetch(`${mcpHost}/actions?since=${Math.max(actionSeq, 0)}`, { headers: { authorization: `Bearer ${agentKey}` } });
    const body = (await response.json()) as { seq: number; events: ActionEvent[] };
    if (actionSeq >= 0) for (const event of body.events) applyAction(event);
    actionSeq = body.seq;
  } catch {
    return;
  }
  hideIdle();
};
if (!location.pathname.startsWith('/settings')) setInterval(() => void pollActions(), 100);

export type TraceLine = { kind: 'thinking' | 'tool' | 'result'; text: string };

const appendTrace = (kind: TraceLine['kind'], text: string) => {
  const last = overlay.trace.at(-1);
  if (kind === 'thinking' && last?.kind === 'thinking') last.text += text;
  else overlay.trace.push({ kind, text });
};

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
  activity: '',
  heard: '',
  settings: undefined as Settings | undefined,
  confirm: undefined as { callId: string; server: string; tool: string; arguments: unknown } | undefined,
  section: '',
  transcript: [] as TranscriptLine[],
  trace: [] as TraceLine[],
  traceOpen: false,
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
    lastFrameAt = Date.now();
    retryMs = 250;
    while (pending.length > 0) socket?.send(pending.shift() ?? '');
  };
  socket.onclose = () => {
    overlay.connected = false;
    socket = undefined;
    setTimeout(connect, retryMs);
    retryMs = Math.min(retryMs * 2, 8000);
  };
  socket.onmessage = (event) => {
    lastFrameAt = Date.now();
    const frame = decodeFrame(event.data);
    if (Option.isNone(frame)) return;
    const value = frame.value;
    if (value.type === 'mcp_call') {
      overlay.activity = `${value.server} · ${value.tool}`;
      const run = () =>
        mcpPost<{ ok: boolean; text: string }>('/call', { server: value.server, tool: value.tool, arguments: value.arguments })
          .catch((error) => ({ ok: false, text: `The t2t MCP host on this Mac is not reachable: ${error}` }))
          .then((result) => send({ type: 'mcp_result', callId: value.callId, ok: result.ok, text: result.text }));
      if (overlay.settings?.confirmMcp) {
        overlay.confirm = { callId: value.callId, server: value.server, tool: value.tool, arguments: value.arguments };
        pendingConfirms.set(value.callId, run);
        shell({ command: 'log', line: `confirm requested ${value.server}.${value.tool}` });
      } else run();
      return;
    }
    if (value.type === 'window') {
      shell({ command: 'window', window: value.window });
      return;
    }
    if (value.type === 'trace') {
      if (value.turnId === overlay.turnId) appendTrace(value.kind, value.text);
      return;
    }
    if (value.type === 'tool') {
      if (value.turnId === overlay.turnId) overlay.activity = value.name === 'writing' ? 'building…' : value.name;
      return;
    }
    if (value.type === 'window_record') {
      shell({ command: 'windowRecord', id: value.id, seconds: value.seconds, path: value.path });
      return;
    }
    if (value.type === 'window_close') {
      shell({ command: 'windowClose', id: value.id });
      return;
    }
    if (value.type === 'windows') {
      shell({ command: 'windows', windows: value.windows });
      return;
    }
    if (value.turnId !== overlay.turnId && value.turnId !== 'none') return;
    if (value.type === 'text') {
      overlay.phase = 'speaking';
      overlay.reply += value.text;
      speakReadySentences(false);
    }
    if (value.type === 'draw') overlay.shapes = [...overlay.shapes, value.shape];
    if (value.type === 'clear') overlay.shapes = [];
    if (value.type === 'done') {
      overlay.activity = '';
      if (!value.reply.startsWith(overlay.reply)) spokenUpTo = Math.min(spokenUpTo, value.reply.length);
      overlay.reply = value.reply;
      overlay.phase = 'idle';
      remember({ mode: 'agent', role: 'agent', text: value.reply });
      speakReadySentences(true);
    }
    if (value.type === 'failed') {
      overlay.lastError = gatewayHint(`${value.step}: ${value.reason}`);
      overlay.phase = 'idle';
      remember({ mode: 'agent', role: 'error', text: overlay.lastError });
    }
  };
};

const pendingConfirms = new Map<string, () => void>();

export const answerConfirm = (allow: boolean) => {
  const current = overlay.confirm;
  if (current === undefined) return;
  overlay.confirm = undefined;
  const run = pendingConfirms.get(current.callId);
  pendingConfirms.delete(current.callId);
  shell({ command: 'log', line: `confirm ${allow ? 'allowed' : 'denied'} ${current.server}.${current.tool}` });
  if (allow) run?.();
  else send({ type: 'mcp_result', callId: current.callId, ok: false, text: 'The user denied this tool call.' });
};

const authFailure = new RegExp('401|403|unauthori[sz]ed|forbidden|cloudflare access|sign.?in|<html', 'i');

const gatewayHint = (message: string) =>
  authFailure.test(message) ? `Opus sign-in expired. Open Settings, General, Model and press Sign in. (${message.slice(0, 160)})` : message;

let spokenUpTo = 0;

const sentenceEnd = /[.!?…](?=\s|$)|[\n]/g;

const speakReadySentences = (final: boolean) => {
  const pending = overlay.reply.slice(spokenUpTo);
  let cut = -1;
  for (const match of pending.matchAll(sentenceEnd)) {
    const end = (match.index ?? 0) + match[0].length;
    if (end >= 12 || final) cut = end;
  }
  if (final) cut = pending.length;
  if (cut <= 0) return;
  const chunk = pending.slice(0, cut).trim();
  spokenUpTo += cut;
  if (chunk !== '') shell({ command: 'speakChunk', text: chunk });
};

const sendTurn = async (text: string, screen: { width: number; height: number }) => {
  const turnId = crypto.randomUUID();
  overlay.turnId = turnId;
  overlay.reply = '';
  overlay.trace = [];
  overlay.lastError = '';
  overlay.activity = '';
  overlay.phase = 'thinking';
  spokenUpTo = 0;
  shell({ command: 'stopSpeaking' });
  const tools = await localTools();
  if (overlay.turnId !== turnId) return;
  if (Date.now() - lastFrameAt > STALE_SOCKET_MS) {
    shell({ command: 'log', line: 'socket idle, reconnecting before the turn' });
    freshSocket();
  }
  send({ type: 'turn', turnId, text, screen, tools });
  watchTurn(turnId);
};

const FIRST_FRAME_MS = 20000;
const STALE_SOCKET_MS = 45000;
let lastFrameAt = Date.now();
let turnWatch: ReturnType<typeof setTimeout> | undefined;
const freshSocket = () => {
  const stale = socket;
  if (stale) {
    stale.onclose = null;
    stale.onmessage = null;
    stale.close();
  }
  socket = undefined;
  connect();
};
const watchTurn = (turnId: string) => {
  clearTimeout(turnWatch);
  const sentAt = Date.now();
  turnWatch = setTimeout(() => {
    if (overlay.turnId !== turnId || overlay.phase !== 'thinking' || lastFrameAt > sentAt) return;
    shell({ command: 'log', line: `turn ${turnId.slice(0, 8)}: no answer in ${FIRST_FRAME_MS / 1000}s` });
    overlay.phase = 'idle';
    overlay.lastError = 'The agent did not answer. Try again.';
    freshSocket();
  }, FIRST_FRAME_MS);
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
  if (event.type === 'stats') {
    stats.value = event.value;
    return;
  }
  if (event.type === 'jobs') {
    jobs.state = event.value;
    return;
  }
  if (event.type === 'jobRun') {
    jobs.error = event.error;
    return;
  }
  if (event.type === 'jobLog') {
    jobs.logs[event.name] = event.text;
    return;
  }
  if (event.type === 'settings') {
    overlay.settings = event.value;
    return;
  }
  if (event.type === 'partial') {
    overlay.heard += event.text;
    return;
  }
  if (event.type === 'hold') {
    overlay.heard = '';
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
      overlay.heard = '';
      if (!event.streamed) shell({ command: 'paste', text: event.text });
    } else sendTurn(event.text, event.screen);
  }
  if (event.type === 'windowClosed') send({ type: 'window_closed', id: event.id });
  if (event.type === 'section') overlay.section = event.value;
  if (event.type === 'confirmAnswer' && overlay.confirm && (event.callId === '' || overlay.confirm.callId === event.callId)) answerConfirm(event.allow);
  if (event.type === 'escape') {
    if (overlay.confirm) return answerConfirm(false);
    dismiss();
  }
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

export type McpState = 'idle' | 'connecting' | 'connected' | 'error' | 'disconnected';
export type McpStatus = { server: string; state: McpState; error?: string; tools: { name: string; description: string }[]; at?: string };

export const mcpStatus = (servers: string[], warm: boolean) => mcpPost<{ servers: McpStatus[] }>('/status', { servers, warm });
export const mcpAction = (action: 'refresh' | 'disconnect' | 'connect', server: string) => mcpPost<McpStatus>(`/${action}`, { server });

export type SavedWindow = {
  id: string;
  title: string;
  kind: 'scene' | 'html';
  summary: string;
  ask: string;
  width: number;
  height: number;
  createdAt: number;
  updatedAt: number;
  opens: number;
  bytes: number;
  open: boolean;
};

const libraryURL = (id?: string) => `${agentBase.replace(/^ws/, 'http')}/agent/library${id === undefined ? '' : `?id=${encodeURIComponent(id)}`}`;

const libraryRequest = async <T,>(method: 'GET' | 'POST' | 'DELETE', id?: string): Promise<T> => {
  const response = await fetch(libraryURL(id), { method, headers: { authorization: `Bearer ${agentKey}` } });
  if (!response.ok) throw new Error(`library ${method} ${response.status}`);
  return response.json() as Promise<T>;
};

export const loadLibrary = () => libraryRequest<{ windows: SavedWindow[] }>('GET').then((body) => body.windows);
export const reopenWindow = (id: string) => libraryRequest<{ ok: boolean }>('POST', id);
export const forgetWindow = (id: string) => libraryRequest<{ ok: boolean }>('DELETE', id);
