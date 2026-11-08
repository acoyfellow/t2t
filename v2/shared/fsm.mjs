export const createMachine = (definition) => {
  const send = (state, event) => definition.transitions[state]?.[event] ?? null;
  const can = (state, event) => send(state, event) !== null;
  return { ...definition, send, can };
};

export const overlayMachine = createMachine({
  initial: 'idle',
  transitions: {
    idle: { HOLD: 'listening' },
    listening: { HOLD: 'listening', RELEASE_AGENT: 'thinking', RELEASE_DICTATE: 'idle', TRANSCRIPT_EMPTY: 'idle', ESCAPE: 'idle' },
    thinking: { HOLD: 'listening', TEXT: 'speaking', DONE: 'idle', FAILED: 'idle', TIMEOUT: 'idle', ESCAPE: 'idle' },
    speaking: { HOLD: 'listening', TEXT: 'speaking', DONE: 'idle', FAILED: 'idle', ESCAPE: 'idle' },
  },
});

export const mcpMachine = createMachine({
  initial: 'idle',
  transitions: {
    idle: { CONNECT: 'connecting' },
    connecting: { CONNECTED: 'connected', NEED_LOGIN: 'login-needed', ERROR: 'error', DISCONNECT: 'disconnected' },
    connected: { REFRESH: 'connecting', NEED_LOGIN: 'login-needed', ERROR: 'error', DISCONNECT: 'disconnected' },
    error: { CONNECT: 'connecting', REFRESH: 'connecting', SIGNIN: 'connecting', DISCONNECT: 'disconnected' },
    'login-needed': { CONNECT: 'connecting', REFRESH: 'connecting', SIGNIN: 'connecting', DISCONNECT: 'disconnected' },
    disconnected: { CONNECT: 'connecting', SIGNIN: 'connecting' },
  },
});

export const gatewayMachine = createMachine({
  initial: 'unknown',
  transitions: {
    unknown: { REFRESH: 'refreshing' },
    refreshing: { OK: 'ok', NEED_LOGIN: 'login-needed', PUSH_FAILED: 'push-failed' },
    ok: { REFRESH: 'refreshing' },
    'login-needed': { REFRESH: 'refreshing' },
    'push-failed': { REFRESH: 'refreshing' },
  },
});

export const holdMachine = createMachine({
  initial: 'none',
  transitions: {
    none: { START_DICTATE: 'dictate', START_AGENT: 'agent' },
    dictate: { START_AGENT: 'agent', STOP: 'none', ESCAPE: 'none' },
    agent: { START_DICTATE: 'dictate', STOP: 'none', ESCAPE: 'none' },
  },
});

export const turnMachine = createMachine({
  initial: 'running',
  transitions: {
    running: { DONE: 'done', FAILED: 'failed', CANCEL: 'cancelled' },
  },
});

export const jobMachine = createMachine({
  initial: 'idle',
  transitions: {
    idle: { START: 'running' },
    running: { FINISH: 'idle', LOST: 'abandoned' },
    abandoned: { START: 'running' },
  },
});

export const indicatorMachine = createMachine({
  initial: 'hidden',
  transitions: {
    hidden: { SHOW: 'active' },
    active: { HIDE: 'hidden' },
  },
});

export const panelMachine = createMachine({
  initial: 'loading',
  transitions: {
    loading: { LOADED: 'ready', FAILED: 'error' },
    ready: { RELOAD: 'loading' },
    error: { RETRY: 'loading' },
  },
});

export const statsMachine = createMachine({
  initial: 'not-imported',
  transitions: {
    'not-imported': { IMPORT: 'imported' },
    imported: { IMPORT: 'imported' },
  },
});

export const machines = {
  overlay: overlayMachine,
  mcp: mcpMachine,
  gateway: gatewayMachine,
  hold: holdMachine,
  turn: turnMachine,
  job: jobMachine,
  indicator: indicatorMachine,
  panel: panelMachine,
  stats: statsMachine,
};
