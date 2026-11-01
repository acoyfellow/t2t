export type CursorTarget = { role: string; name: string; x: number; y: number; w: number; h: number };

export type ActionEvent = {
  seq: number;
  server: string;
  phase: 'before' | 'after';
  agent: string;
  app: string;
  action: string;
  target?: CursorTarget;
  ok: boolean;
  code?: string;
};

export type AgentCursor = {
  agent: string;
  x: number;
  y: number;
  travelMs: number;
  color: string;
  label: string;
  phase: 'before' | 'after';
  ok: boolean;
  visible: boolean;
  target?: CursorTarget;
  lastAt: number;
};

const AGENT_COLORS = ['#c27aff', '#00ffa3', '#38bdf8', '#fbbf24', '#f472b6', '#a3e635'];
const HIDE_AFTER_MS = 2500;

export const cursors = $state({ byAgent: {} as Record<string, AgentCursor> });

const verbs: Record<string, string> = { press: 'Clicking', set: 'Typing into', focus: 'Focusing', confirm: 'Confirming' };

export const describeAction = (event: ActionEvent): string => {
  const what = event.target?.name ? `"${event.target.name.slice(0, 28)}"` : (event.target?.role ?? event.app);
  if (event.phase === 'after' && !event.ok) return `${event.code ?? 'failed'} · ${what}`;
  return `${verbs[event.action] ?? event.action} ${what}`;
};

export const travelTime = (from: { x: number; y: number }, to: { x: number; y: number }): number => {
  const distance = Math.hypot(to.x - from.x, to.y - from.y);
  return Math.round(Math.min(420, Math.max(120, 90 + distance * 0.25)));
};

export const applyAction = (event: ActionEvent, now = Date.now()): void => {
  const existing = cursors.byAgent[event.agent];
  const index = Object.keys(cursors.byAgent).length;
  const color = existing?.color ?? AGENT_COLORS[index % AGENT_COLORS.length] ?? '#c27aff';
  const point = event.target ? { x: event.target.x + Math.min(event.target.w / 2, 40), y: event.target.y + event.target.h / 2 } : { x: existing?.x ?? 0, y: existing?.y ?? 0 };
  const from = existing ?? { x: point.x - 120, y: point.y - 80 };
  cursors.byAgent[event.agent] = {
    agent: event.agent,
    x: point.x,
    y: point.y,
    travelMs: travelTime(from, point),
    color,
    label: describeAction(event),
    phase: event.phase,
    ok: event.ok,
    visible: true,
    target: event.target,
    lastAt: now,
  };
};

export const hideIdle = (now = Date.now()): void => {
  for (const cursor of Object.values(cursors.byAgent)) if (cursor.visible && now - cursor.lastAt > HIDE_AFTER_MS) cursor.visible = false;
};
