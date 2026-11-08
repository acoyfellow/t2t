import { KIT_SOURCE } from './kit.generated.ts';
import { BACKGROUND_CONTEXT } from '@earendil-works/chord/context';
import { Type } from '@earendil-works/pi-ai';
import { createModels } from '@earendil-works/pi-ai/models';
import { cloudflareWorkersAIProvider } from '@earendil-works/pi-ai/providers/cloudflare-workers-ai';
import {
  type AgentEvent,
  type Conversation,
  createRegistry,
  defineExtension,
  defineTool,
  Harness,
  section,
  watchEvents,
} from '@earendil-works/pi-durable';
import { openDurableObjectSqliteStorage } from '@earendil-works/pi-durable/storage/sqlite/cloudflare';
import { DurableObject } from 'cloudflare:workers';
import * as Effect from 'effect/Effect';
import * as Option from 'effect/Option';
import * as Schema from 'effect/Schema';
import { turnNext } from './turnMachine.ts';
import {
  ClientFrameJson,
  type DrawShape,
  type McpTool,
  type ServerFrame,
  ServerFrameJson,
  type AgentWindow,
  type TurnRecord,
  TurnRecordsJson,
  type TurnRequest,
} from '../../shared/protocol';
import { bindingAuthContext, GATEWAY_PROVIDER, type GatewayEnv, gatewayProvider, tokenExpiry, routeWorkersAIThroughBinding } from './model';

export type AgentEnv = GatewayEnv & { readonly AI: Ai; readonly MODEL: string; readonly GATEWAY: string };

const CONTEXT = BACKGROUND_CONTEXT;

const RECORD_LIMIT = 200;

const UNANSWERED_MEANING: Readonly<Record<string, string>> = {
  model_error: 'the model call failed',
  aborted: 'the turn was cancelled',
  overflow: 'the conversation is too long for the model',
  no_model: 'no model is configured',
  restart_limit: 'the agent restarted too many times',
  stale: 'the turn waited too long and expired',
  faulted: 'the agent crashed',
};

const unansweredReason = (settled: { status: string; reason?: string; detail?: unknown }) => {
  const reason = settled.reason ?? 'unknown';
  const meaning = UNANSWERED_MEANING[reason] ?? reason;
  const detail = settled.detail === undefined ? '' : `: ${typeof settled.detail === 'string' ? settled.detail : JSON.stringify(settled.detail)}`;
  return `${meaning} (${reason})${detail}`.slice(0, 400);
};

const clip = (value: string, limit: number) => (value.length > limit ? `${value.slice(0, limit)}…` : value);

const traceArgs = (event: { args?: unknown }) => clip(JSON.stringify(event.args ?? {}), 240);

const traceResult = (event: { entry?: unknown; result?: unknown }) => {
  const messages = (event.entry as { model?: { content?: { type: string; text?: string }[]; isError?: boolean }[] } | undefined)?.model ?? [];
  const message = messages.at(-1);
  const fromEntry = message?.content?.map((part) => part.text ?? `[${part.type}]`).join(' ');
  const output = (event.result as { output?: unknown } | undefined)?.output;
  const body = fromEntry ?? (typeof output === 'string' ? output : JSON.stringify(output ?? ''));
  return `${message?.isError ? 'error: ' : ''}${clip(body.replace(/\s+/g, ' '), 300)}`;
};
const MCP_CALL_TIMEOUT_MS = 75_000;

const DEMO_BRIEF = [
  'When the user asks to show, explain, visualise or demo how something works, call scene_open. Write only the scene: regions, boxes, wires and 3 to 6 steps. The kit draws it in a polished, consistent style and animates it.',
  'Scene rules: lowercase, short, true. Box label is 1 to 3 words; kicker is a 1 to 2 word role. Captions are one plain sentence. Place boxes on a grid inside a 1100x470 canvas: boxes 160 to 200 wide, 76 tall, at least 50 apart. Use regions for places (your mac, cloudflare, browser). Each step lights the boxes that act and flows the wires that carry data. Wire ids default to "from>to".',
  'If the user asks for a video, call window_record on the scene id with seconds equal to the total step time (2.2s per step, 3.6s for the last, unless you set ms).',
  'Use window_open only for things the kit cannot show, such as charts, tables, forms or 3d.',
  '',
  'Every window you make is saved. Each request lists past windows that may match. Before you build anything, check them:',
  '- If one already answers the request, call window_reopen. Do not rebuild it.',
  '- If one is close, call window_read, change only what differs, and save it with the same id.',
  '- Build from scratch only when nothing fits. Say in your reply when you reused or changed an old window.',
  'Use window_search when the user refers to earlier work ("the auth diagram", "that chart from yesterday").',
].join('\n');

const PROMPT = [
  'You are the voice assistant inside t2t on a Mac. The user speaks, you answer briefly.',
  'You can draw on top of the user screen with the draw tool. Coordinates are screen points from the top-left corner.',
  'Use draw to point at things, show layouts, or sketch an answer. Use clear_screen to remove your drawings.',
  'Answer in one or two short spoken sentences. No markdown. Windows you open can be as long and detailed as they need to be.',
  'The user may have local MCP tools on their Mac. They are listed with each request. Call mcp_describe to read a tool input schema, then mcp_call to run it.',
  'Only call MCP tools the request needs. Say plainly what a tool returned. If a tool needs a login, tell the user which command to run.',
  '',
  DEMO_BRIEF,
].join('\n');

export class HarnessFailed extends Schema.TaggedError<HarnessFailed>()('HarnessFailed', { step: Schema.String, reason: Schema.String }) {}

const pi = <A>(step: string, run: () => Promise<A>) =>
  Effect.tryPromise({ try: run, catch: (cause) => new HarnessFailed({ step, reason: String(cause) }) });

const text = (value: string) => ({ output: [{ type: 'text' as const, text: value }] });

const encodeFrame = Schema.encodeSync(ServerFrameJson);
const decodeClient = Schema.decodeUnknownOption(ClientFrameJson);
const encodeRecords = Schema.encodeSync(TurnRecordsJson);
const decodeRecords = Schema.decodeUnknownOption(TurnRecordsJson);

type Live = { readonly harness: Harness; readonly conversation: Conversation };

type Active = { turnId: string; ask: string; draws: DrawShape[]; tools: string[] };

type LibraryEntry = {
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
};

const LIBRARY_LIMIT = 300;
const RECALL_LIMIT = 5;

const wordsOf = (value: string) => new Set(value.toLowerCase().match(/[a-z0-9]{3,}/g) ?? []);

const relevance = (entry: LibraryEntry, query: Set<string>) => {
  const words = wordsOf(`${entry.title} ${entry.summary} ${entry.ask} ${entry.id.replace(/-/g, ' ')}`);
  return [...query].filter((word) => words.has(word)).length;
};

const ago = (at: number) => {
  const minutes = Math.round((Date.now() - at) / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  return hours < 48 ? `${hours}h ago` : `${Math.round(hours / 24)}d ago`;
};

const describeEntry = (entry: LibraryEntry) => `${entry.id} [${entry.kind}] "${entry.title}" — ${entry.summary} (${ago(entry.updatedAt)}, ${entry.bytes} chars)`;

const sceneSummary = (scene: { subtitle?: string; boxes: readonly { label: string }[]; steps: readonly { label: string }[] }) =>
  [scene.subtitle, `boxes: ${scene.boxes.map((box) => box.label).join(', ')}`, `steps: ${scene.steps.map((step) => step.label).join(' → ')}`].filter(Boolean).join('; ');

const htmlSummary = (html: string) =>
  html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);

const assistantMessages = (events: readonly AgentEvent[]) =>
  events.flatMap((event) => (event.type === 'message_end' ? (event.entry.model ?? []) : [])).flatMap((message) =>
    message.role === 'assistant' ? [message] : [],
  );

const costOf = (events: readonly AgentEvent[]): number =>
  assistantMessages(events).reduce((sum, message) => sum + message.usage.cost.total, 0);

const replyOf = (events: readonly AgentEvent[]): Option.Option<string> => {
  const ends = assistantMessages(events);
  const last = ends.at(-1);
  if (last === undefined) return Option.none();
  const said = last.content.flatMap((block) => (block.type === 'text' ? [block.text] : [])).join('');
  return said === '' ? Option.none() : Option.some(said);
};

const textOfMessage = (message: { content: readonly { type: string; text?: string }[] } | undefined) =>
  message === undefined ? undefined : message.content.flatMap((block) => (block.type === 'text' && block.text !== undefined ? [block.text] : [])).join('');

const thinkingOfMessage = (message: { content: readonly { type: string; thinking?: string }[] } | undefined) =>
  message?.content.flatMap((block) => (block.type === 'thinking' && block.thinking !== undefined ? [block.thinking] : [])).join('\n\n');

const thinkingOf = (event: AgentEvent): string | undefined => {
  if (event.type === 'message_start') return event.message.role === 'assistant' ? thinkingOfMessage(event.message) : undefined;
  if (event.type !== 'message_update') return undefined;
  const whole = event.changes.findLast((change) => change.type === 'message');
  return whole?.type === 'message' ? thinkingOfMessage(whole.message) : undefined;
};

const streamedTextOf = (event: AgentEvent): string | undefined => {
  if (event.type === 'snapshot') return textOfMessage(event.generation?.message);
  if (event.type === 'message_start') return event.message.role === 'assistant' ? textOfMessage(event.message) : undefined;
  if (event.type === 'message_update') {
    const whole = event.changes.findLast((change) => change.type === 'message');
    return whole?.type === 'message' ? textOfMessage(whole.message) : undefined;
  }
  return undefined;
};

export class Agent extends DurableObject<AgentEnv> {
  private live: Option.Option<Promise<Live>> = Option.none();
  private active: Option.Option<Active> = Option.none();
  private catalog: readonly McpTool[] = [];
  private pendingCalls = new Map<string, (result: { ok: boolean; text: string }) => void>();

  private callLocal(server: string, tool: string, args: unknown): Promise<{ ok: boolean; text: string }> {
    const turnId = Option.match(this.active, { onNone: () => 'none', onSome: (active) => active.turnId });
    const callId = crypto.randomUUID();
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingCalls.delete(callId);
        resolve({ ok: false, text: `The Mac did not answer the ${server}.${tool} call in time.` });
      }, MCP_CALL_TIMEOUT_MS);
      this.pendingCalls.set(callId, (result) => {
        clearTimeout(timer);
        this.pendingCalls.delete(callId);
        resolve(result);
      });
      this.broadcast({ type: 'mcp_call', turnId, callId, server, tool, arguments: args });
    });
  }

  constructor(ctx: DurableObjectState, env: AgentEnv) {
    super(ctx, env);
    routeWorkersAIThroughBinding(env.AI, env.GATEWAY);
  }

  private gatewayToken(): string {
    const stored = this.ctx.storage.kv.get<string>('gatewayToken');
    const candidates = [stored, this.env.LLM_GATEWAY_TOKEN].filter((token): token is string => token !== undefined && token !== '');
    return candidates.sort((left, right) => (tokenExpiry(right) ?? 0) - (tokenExpiry(left) ?? 0))[0] ?? '';
  }

  private gatewayStatus() {
    const expires = tokenExpiry(this.gatewayToken());
    return { expiresAt: expires ?? null, hoursLeft: expires === undefined ? null : Math.round((expires - Date.now()) / 36e5) };
  }

  private broadcast(frame: ServerFrame): void {
    const encoded = encodeFrame(frame);
    for (const socket of this.ctx.getWebSockets()) socket.send(encoded);
  }

  private records(): TurnRecord[] {
    const raw = this.ctx.storage.kv.get<string>('turns');
    return raw === undefined ? [] : [...Option.getOrElse(decodeRecords(raw), () => [])];
  }

  private saveRecord(record: TurnRecord): void {
    const rest = this.records().filter((existing) => existing.turnId !== record.turnId);
    this.ctx.storage.kv.put('turns', encodeRecords([...rest, record].slice(-RECORD_LIMIT)));
  }

  private windows(): AgentWindow[] {
    return this.ctx.storage.kv.get<AgentWindow[]>('windows') ?? [];
  }

  private saveWindows(next: AgentWindow[]): void {
    this.ctx.storage.kv.put('windows', next);
  }

  private library(): LibraryEntry[] {
    return this.ctx.storage.kv.get<LibraryEntry[]>('library') ?? this.seedLibrary();
  }

  private seedLibrary(): LibraryEntry[] {
    const seeded = this.windows().map((window) => this.entryFor(window, 'html', htmlSummary(window.html), '', undefined));
    for (const window of this.windows()) this.ctx.storage.kv.put(`library:${window.id}:html`, window.html);
    this.ctx.storage.kv.put('library', seeded);
    return seeded;
  }

  private entryFor(window: AgentWindow, kind: LibraryEntry['kind'], summary: string, ask: string, previous: LibraryEntry | undefined): LibraryEntry {
    return {
      id: window.id,
      title: window.title,
      kind,
      summary,
      ask: ask || previous?.ask || '',
      width: window.width,
      height: window.height,
      createdAt: previous?.createdAt ?? window.updatedAt,
      updatedAt: window.updatedAt,
      opens: (previous?.opens ?? 0) + 1,
      bytes: window.html.length,
    };
  }

  private remember(window: AgentWindow, kind: LibraryEntry['kind'], summary: string, source: string): void {
    const existing = this.library();
    const previous = existing.find((entry) => entry.id === window.id);
    const ask = Option.match(this.active, { onNone: () => '', onSome: (active) => active.ask });
    const entry = this.entryFor(window, kind, summary, ask, previous);
    const next = [...existing.filter((candidate) => candidate.id !== window.id), entry].sort((left, right) => right.updatedAt - left.updatedAt);
    for (const dropped of next.slice(LIBRARY_LIMIT)) {
      this.ctx.storage.kv.delete(`library:${dropped.id}:html`);
      this.ctx.storage.kv.delete(`library:${dropped.id}:source`);
    }
    this.ctx.storage.kv.put('library', next.slice(0, LIBRARY_LIMIT));
    this.ctx.storage.kv.put(`library:${window.id}:html`, window.html);
    this.ctx.storage.kv.put(`library:${window.id}:source`, source);
  }

  private reopen(id: string): AgentWindow | undefined {
    const entry = this.library().find((candidate) => candidate.id === id);
    const html = this.ctx.storage.kv.get<string>(`library:${id}:html`);
    if (entry === undefined || html === undefined) return undefined;
    const window: AgentWindow = { id, title: entry.title, html, width: entry.width, height: entry.height, updatedAt: Date.now() };
    this.saveWindows([...this.windows().filter((open) => open.id !== id), window]);
    this.ctx.storage.kv.put('library', this.library().map((candidate) => (candidate.id === id ? { ...candidate, opens: candidate.opens + 1, updatedAt: window.updatedAt } : candidate)));
    this.broadcast({ type: 'window', turnId: this.currentTurnId(), window });
    return window;
  }

  private forget(id: string): boolean {
    const existing = this.library();
    if (!existing.some((entry) => entry.id === id)) return false;
    this.ctx.storage.kv.put('library', existing.filter((entry) => entry.id !== id));
    this.ctx.storage.kv.delete(`library:${id}:html`);
    this.ctx.storage.kv.delete(`library:${id}:source`);
    return true;
  }

  private recall(ask: string): string {
    const entries = this.library();
    if (entries.length === 0) return '';
    const query = wordsOf(ask);
    const ranked = entries
      .map((entry) => ({ entry, score: relevance(entry, query) }))
      .sort((left, right) => right.score - left.score || right.entry.updatedAt - left.entry.updatedAt);
    const matches = ranked.filter((candidate) => candidate.score > 0).slice(0, RECALL_LIMIT);
    const picked = matches.length > 0 ? matches : ranked.slice(0, 3);
    const heading = matches.length > 0 ? 'Past windows that may match' : 'Most recent past windows';
    return `\n\n(${heading}, ${entries.length} saved in all: ${picked.map(({ entry }) => describeEntry(entry)).join('; ')})`;
  }

  private currentTurnId(): string {
    return Option.match(this.active, { onNone: () => 'none', onSome: (active) => active.turnId });
  }

  private windowTools() {
    return [
      defineTool({
        name: 'window_open',
        description:
          'Open or replace a floating window on the user Mac that shows a complete HTML document you write. Use it for anything visual that should stay: canvases, three.js scenes (load from https://unpkg.com or https://esm.sh), charts, notes, dashboards. The window stays open across restarts until the user or you close it. Reusing an id replaces that window.',
        parameters: Type.Object({
          id: Type.Optional(Type.String({ description: 'Short stable id such as "solar-system". Omit to create a new one.' })),
          title: Type.String(),
          html: Type.String({ description: 'A full HTML document. Inline CSS and JS. External scripts over https are allowed.' }),
          width: Type.Optional(Type.Number()),
          height: Type.Optional(Type.Number()),
        }),
        replay: 'safe',
        execute: async ({ id, title, html, width, height }) => {
          const existing = this.windows();
          const windowId = id ?? `w-${crypto.randomUUID().slice(0, 8)}`;
          const previous = existing.find((entry) => entry.id === windowId);
          const next: AgentWindow = {
            id: windowId,
            title,
            html,
            width: width ?? previous?.width ?? 640,
            height: height ?? previous?.height ?? 480,
            updatedAt: Date.now(),
          };
          this.saveWindows([...existing.filter((entry) => entry.id !== windowId), next]);
          this.remember(next, 'html', htmlSummary(html), html);
          Option.map(this.active, (active) => active.tools.push(`window_open:${windowId}`));
          this.broadcast({ type: 'window', turnId: this.currentTurnId(), window: next });
          return text(`${previous ? 'Replaced' : 'Opened'} window ${windowId} (${next.width}x${next.height}).`);
        },
      }),
      defineTool({
        name: 'window_list',
        description: 'List the windows you have open on the user Mac, with ids, titles and sizes.',
        parameters: Type.Object({}),
        replay: 'safe',
        execute: async () => {
          const open = this.windows();
          return text(open.length === 0 ? 'No windows open.' : open.map((entry) => `${entry.id} "${entry.title}" ${entry.width}x${entry.height} (${entry.html.length} chars)`).join('\n'));
        },
      }),
      defineTool({
        name: 'window_read',
        description: 'Read the source of a window, open or saved: the scene JSON for scenes, the HTML for others. Use it to edit an old window instead of writing a new one.',
        parameters: Type.Object({ id: Type.String() }),
        replay: 'safe',
        execute: async ({ id }) => {
          const source = this.ctx.storage.kv.get<string>(`library:${id}:source`) ?? this.windows().find((entry) => entry.id === id)?.html;
          return text(source ?? `No window ${id}.`);
        },
      }),
      defineTool({
        name: 'window_search',
        description: 'Search every window you have ever made, open or closed, by words in the title, contents or the request that made it. Returns ids to reopen or edit.',
        parameters: Type.Object({ query: Type.String() }),
        replay: 'safe',
        execute: async ({ query }) => {
          const words = wordsOf(query);
          const hits = this.library()
            .map((entry) => ({ entry, score: relevance(entry, words) }))
            .filter((candidate) => candidate.score > 0)
            .sort((left, right) => right.score - left.score || right.entry.updatedAt - left.entry.updatedAt)
            .slice(0, 10);
          return text(hits.length === 0 ? `No saved window matches "${query}".` : hits.map(({ entry }) => describeEntry(entry)).join('\n'));
        },
      }),
      defineTool({
        name: 'window_reopen',
        description: 'Open a saved window again exactly as it was. It costs almost nothing, so prefer it over making a new window when an old one answers the request.',
        parameters: Type.Object({ id: Type.String() }),
        replay: 'safe',
        execute: async ({ id }) => {
          const window = this.reopen(id);
          Option.map(this.active, (active) => active.tools.push(`window_reopen:${id}`));
          return text(window ? `Reopened window ${id}.` : `No saved window ${id}. Try window_search.`);
        },
      }),
      defineTool({
        name: 'scene_open',
        description: 'Open an animated explainer window from a scene description. The kit renders boxes, wires, regions, a step list and captions, and loops the steps.',
        parameters: Type.Object({
          id: Type.String({ description: 'Short stable id such as "how-auth-works".' }),
          scene: Type.Object({
            palette: Type.Optional(Type.Union([Type.Literal('night'), Type.Literal('paper')])),
            title: Type.String(),
            subtitle: Type.Optional(Type.String()),
            regions: Type.Optional(Type.Array(Type.Object({ label: Type.String(), x: Type.Number(), y: Type.Number(), w: Type.Number(), h: Type.Number() }))),
            boxes: Type.Array(Type.Object({ id: Type.String(), label: Type.String(), kicker: Type.Optional(Type.String()), x: Type.Number(), y: Type.Number(), w: Type.Number(), h: Type.Number() })),
            wires: Type.Optional(Type.Array(Type.Object({ from: Type.String(), to: Type.String(), id: Type.Optional(Type.String()), label: Type.Optional(Type.String()), route: Type.Optional(Type.Literal('below')) }))),
            steps: Type.Array(Type.Object({ label: Type.String(), caption: Type.Optional(Type.String()), lit: Type.Optional(Type.Array(Type.String())), flow: Type.Optional(Type.Array(Type.String())), ms: Type.Optional(Type.Number()) })),
          }),
        }),
        replay: 'safe',
        execute: async ({ id, scene }) => {
          const html = `<!doctype html><html><head><meta charset="utf-8"><title>${scene.title}</title><style id="kit-css"></style></head><body><script>\n${KIT_SOURCE}\ndocument.getElementById('kit-css').textContent = css;\nplay(${JSON.stringify(scene).replace(/</g, '\\u003c')});\n</script></body></html>`;
          const entry = { id, title: scene.title, html, width: 1200, height: 760, updatedAt: Date.now() };
          this.saveWindows([...this.windows().filter((existing) => existing.id !== id), entry]);
          this.remember(entry, 'scene', sceneSummary(scene), JSON.stringify(scene));
          this.broadcast({ type: 'window', turnId: this.currentTurnId(), window: entry });
          const total = scene.steps.reduce((sum, step, index) => sum + (step.ms ?? (index === scene.steps.length - 1 ? 3600 : 2200)), 0);
          return text(`Opened scene ${id}. One loop is ${Math.ceil(total / 1000)}s.`);
        },
      }),
      defineTool({
        name: 'window_record',
        description:
          'Record one of your windows to an mp4 on the user Mac. The window reloads first, so the recording starts at the beginning of your animation. Use it after window_open when the user asks for a demo, a video or a clip. Recording runs in the background; say where the file will be.',
        parameters: Type.Object({
          id: Type.String(),
          seconds: Type.Number({ description: 'Length in seconds, 2 to 30. Match one full loop of the animation.' }),
        }),
        replay: 'unsafe',
        execute: async ({ id, seconds }) => {
          if (!this.windows().some((entry) => entry.id === id)) return text(`No window ${id}. Open it with window_open first.`);
          const length = Math.min(30, Math.max(2, Math.round(seconds)));
          const path = `~/Movies/t2t/${id}-${Date.now()}.mp4`;
          this.broadcast({ type: 'window_record', turnId: this.currentTurnId(), id, seconds: length, path });
          return text(`Recording ${id} for ${length}s to ${path}.`);
        },
      }),
      defineTool({
        name: 'window_close',
        description: 'Close one of your windows on the user Mac.',
        parameters: Type.Object({ id: Type.String() }),
        replay: 'safe',
        execute: async ({ id }) => {
          const existing = this.windows();
          if (!existing.some((entry) => entry.id === id)) return text(`No window ${id}.`);
          this.saveWindows(existing.filter((entry) => entry.id !== id));
          this.broadcast({ type: 'window_close', turnId: this.currentTurnId(), id });
          return text(`Closed window ${id}. It stays saved; window_reopen brings it back.`);
        },
      }),
    ];
  }

  private tools() {
    return [
      ...this.windowTools(),
      defineTool({
        name: 'draw',
        description: 'Draw a shape on top of the user screen. kind is box, arrow, text or highlight. x, y, w, h are screen points.',
        parameters: Type.Object({
          kind: Type.Union([Type.Literal('box'), Type.Literal('arrow'), Type.Literal('text'), Type.Literal('highlight')]),
          x: Type.Number(),
          y: Type.Number(),
          w: Type.Number(),
          h: Type.Number(),
          label: Type.Optional(Type.String()),
          color: Type.Optional(Type.String()),
        }),
        replay: 'safe',
        execute: async (args) => {
          const turnId = Option.match(this.active, { onNone: () => 'none', onSome: (active) => active.turnId });
          const shape: DrawShape = { id: crypto.randomUUID(), ...args };
          Option.map(this.active, (active) => active.draws.push(shape));
          this.broadcast({ type: 'draw', turnId, shape });
          return text(`Drew ${args.kind} at ${args.x},${args.y}.`);
        },
      }),
      defineTool({
        name: 'mcp_describe',
        description: 'Read the description and JSON input schema of one local MCP tool before calling it.',
        parameters: Type.Object({ server: Type.String(), tool: Type.String() }),
        replay: 'safe',
        execute: async ({ server, tool }) => {
          const found = this.catalog.find((entry) => entry.server === server && entry.name === tool);
          if (found === undefined) return text(`No tool ${tool} on ${server}. Available: ${this.catalog.map((entry) => `${entry.server}.${entry.name}`).join(', ')}`);
          return text(`${found.description}\n\nInput schema:\n${JSON.stringify(found.inputSchema)}`);
        },
      }),
      defineTool({
        name: 'mcp_call',
        description: 'Run one local MCP tool on the user Mac. arguments must match the tool input schema.',
        parameters: Type.Object({ server: Type.String(), tool: Type.String(), arguments: Type.Optional(Type.Record(Type.String(), Type.Unknown())) }),
        replay: 'unsafe',
        execute: async ({ server, tool, arguments: args }) => {
          Option.map(this.active, (active) => active.tools.push(`${server}.${tool}`));
          const result = await this.callLocal(server, tool, args ?? {});
          const body = result.text.length > 12000 ? `${result.text.slice(0, 12000)}\n[truncated]` : result.text;
          return text(result.ok ? body : `Tool error: ${body}`);
        },
      }),
      defineTool({
        name: 'clear_screen',
        description: 'Remove every drawing from the user screen.',
        parameters: Type.Object({}),
        replay: 'safe',
        execute: async () => {
          const turnId = Option.match(this.active, { onNone: () => 'none', onSome: (active) => active.turnId });
          this.broadcast({ type: 'clear', turnId });
          return text('Cleared the screen.');
        },
      }),
    ];
  }

  private open(): Promise<Live> {
    return Option.getOrElse(this.live, () => {
      const opening = Effect.runPromise(
        Effect.gen({ self: this }, function* () {
          const models = createModels({ authContext: bindingAuthContext });
          const workersAI = cloudflareWorkersAIProvider();
          models.setProvider(workersAI);
          models.setProvider(gatewayProvider(this.env, () => this.gatewayToken()));
          const provider = this.env.MODEL.startsWith('claude-') ? { id: GATEWAY_PROVIDER } : workersAI;
          const registry = createRegistry();
          registry.install(
            defineExtension({ name: 't2t', sections: [section('preamble', () => PROMPT, { tag: false })], tools: this.tools() }),
          );
          const storage = yield* pi('storage', () => openDurableObjectSqliteStorage(this.ctx.storage));
          const harness = yield* pi('open', async () => Harness.open(storage, { models, registry }, CONTEXT));
          const conversation = yield* pi('root', () =>
            harness.root(CONTEXT, { agent: { model: { provider: provider.id, modelId: this.env.MODEL } } }),
          );
          yield* pi('configure', () => conversation.configure({ model: { provider: provider.id, modelId: this.env.MODEL }, thinkingLevel: 'low' }, CONTEXT));
          harness.resume();
          return { harness, conversation };
        }),
      );
      this.live = Option.some(opening);
      opening.catch(() => {
        this.live = Option.none();
      });
      return opening;
    });
  }

  private runTurn(request: TurnRequest) {
    return Effect.gen({ self: this }, function* () {
      const started = Date.now();
      const active: Active = { turnId: request.turnId, ask: request.text, draws: [], tools: [] };
      this.active = Option.some(active);
      this.saveRecord({ turnId: request.turnId, startedAt: started, input: request.text, status: 'running', tools: [], draws: [], usd: 0 });
      const { harness, conversation } = yield* pi('open', () => this.open());
      const seen: AgentEvent[] = [];
      let streamedSoFar = '';
      let broadcastLength = 0;
      let thoughtLength = 0;
      let lastBeat = 0;
      const stream = yield* pi('watch', () => watchEvents(harness, conversation.id, CONTEXT));
      stream.start(async (events) => {
        seen.push(...events);
        for (const event of events) {
          if (event.type === 'tool_execution_start') {
            lastBeat = Date.now();
            active.tools.push(event.toolName);
            this.broadcast({ type: 'tool', turnId: request.turnId, name: event.toolName });
            this.broadcast({ type: 'trace', turnId: request.turnId, kind: 'tool', text: `${event.toolName} ${traceArgs(event)}` });
          }
          if (event.type === 'tool_execution_end') {
            this.broadcast({ type: 'trace', turnId: request.turnId, kind: 'result', text: traceResult(event) });
          }
          if (event.type === 'message_end') {
            const finalThinking = (event.entry.model ?? []).flatMap((message) => (message.role === 'assistant' ? [thinkingOfMessage(message) ?? ''] : [])).join('');
            if (finalThinking.length > thoughtLength) this.broadcast({ type: 'trace', turnId: request.turnId, kind: 'thinking', text: finalThinking.slice(thoughtLength) });
            streamedSoFar = '';
            broadcastLength = 0;
            thoughtLength = 0;
            continue;
          }
          const thinking = thinkingOf(event);
          if (thinking !== undefined && thinking.length > thoughtLength) {
            this.broadcast({ type: 'trace', turnId: request.turnId, kind: 'thinking', text: thinking.slice(thoughtLength) });
            thoughtLength = thinking.length;
          }
          const known = streamedTextOf(event);
          if (known !== undefined && known.length > broadcastLength && known.startsWith(streamedSoFar.slice(0, broadcastLength))) {
            this.broadcast({ type: 'text', turnId: request.turnId, text: known.slice(broadcastLength) });
            streamedSoFar = known;
            broadcastLength = known.length;
          } else if (event.type === 'message_update') {
            const writingTool = event.changes.some((change) => change.type.startsWith('toolcall'));
            if (writingTool && Date.now() - lastBeat > 3000) {
              lastBeat = Date.now();
              this.broadcast({ type: 'tool', turnId: request.turnId, name: 'writing' });
            }
            const deltas = event.changes.flatMap((change) =>
              change.type === 'text_delta' ? [change.delta] : change.type === 'text_start' && change.block.type === 'text' ? [change.block.text] : [],
            );
            const appended = deltas.join('');
            if (appended !== '') {
              streamedSoFar += appended;
              this.broadcast({ type: 'text', turnId: request.turnId, text: appended });
              broadcastLength = streamedSoFar.length;
            }
          }
        }
      });
      const screen = request.screen === undefined ? '' : `\n\n(Screen is ${request.screen.width}x${request.screen.height} points.)`;
      this.catalog = request.tools ?? [];
      const firstSentence = (value: string) => value.split(/(?<=[.!?])\s/)[0]?.slice(0, 160) ?? '';
      const toolList =
        this.catalog.length === 0
          ? ''
          : `\n\n(Local MCP tools: ${this.catalog.map((entry) => `${entry.server}.${entry.name} — ${firstSentence(entry.description)}`).join('; ')})`;
      const recalled = this.recall(request.text);
      const submission = yield* pi('submit', () =>
        conversation.submit({ type: 'input', content: `${request.text}${screen}${toolList}${recalled}`, requestId: request.turnId }, CONTEXT),
      );
      const heartbeat = setInterval(() => this.broadcast({ type: 'tool', turnId: request.turnId, name: 'writing' }), 5000);
      const settled = yield* pi('wait', () => submission.wait(CONTEXT)).pipe(Effect.ensuring(Effect.sync(() => clearInterval(heartbeat))));
      yield* Effect.promise(() => stream.stop());
      const usd = costOf(seen);
      const reply = Option.getOrElse(replyOf(seen), () => '');
      if (settled.status !== 'done') {
        return yield* Effect.fail(new HarnessFailed({ step: 'settle', reason: unansweredReason(settled) }));
      }
      this.saveRecord({
        turnId: request.turnId,
        startedAt: started,
        endedAt: Date.now(),
        input: request.text,
        status: turnNext('running', 'DONE') ?? 'done',
        reply,
        tools: active.tools,
        draws: active.draws,
        usd,
      });
      this.broadcast({ type: 'done', turnId: request.turnId, reply, usd });
    }).pipe(
      Effect.catchTag('HarnessFailed', (failure) =>
        Effect.sync(() => {
          const active = Option.getOrUndefined(this.active);
          this.saveRecord({
            turnId: request.turnId,
            startedAt: Date.now(),
            endedAt: Date.now(),
            input: request.text,
            status: turnNext('running', 'FAILED') ?? 'failed',
            tools: active?.tools ?? [],
            draws: active?.draws ?? [],
            usd: 0,
            error: { step: failure.step, reason: failure.reason },
          });
          this.broadcast({ type: 'failed', turnId: request.turnId, step: failure.step, reason: failure.reason });
        }),
      ),
      Effect.ensuring(Effect.sync(() => {
        this.active = Option.none();
      })),
    );
  }

  private cancel(turnId: string) {
    return pi('open', () => this.open()).pipe(
      Effect.flatMap(({ conversation }) => pi('abort', () => conversation.abort(CONTEXT))),
      Effect.tap(() =>
        Effect.sync(() => {
          const record = this.records().find((existing) => existing.turnId === turnId);
          if (record !== undefined) this.saveRecord({ ...record, status: turnNext(record.status, 'CANCEL') ?? record.status, endedAt: Date.now() });
        }),
      ),
      Effect.ignore,
    );
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.endsWith('/gateway-token')) {
      if (request.method === 'PUT') {
        const token = (await request.text()).trim();
        const expires = tokenExpiry(token);
        if (expires === undefined || expires < Date.now()) return Response.json({ ok: false, error: 'token is not a live JWT' }, { status: 400 });
        if (expires > (tokenExpiry(this.gatewayToken()) ?? 0)) this.ctx.storage.kv.put('gatewayToken', token);
      }
      return Response.json({ ok: true, ...this.gatewayStatus() });
    }
    if (url.pathname.endsWith('/library')) {
      const id = url.searchParams.get('id') ?? '';
      if (request.method === 'POST') return Response.json({ ok: this.reopen(id) !== undefined });
      if (request.method === 'DELETE') return Response.json({ ok: this.forget(id) });
      const open = new Set(this.windows().map((window) => window.id));
      return Response.json({ windows: this.library().map((entry) => ({ ...entry, open: open.has(entry.id) })) });
    }
    if (url.pathname.endsWith('/turns')) {
      return new Response(encodeRecords(this.records().slice().reverse()), { headers: { 'content-type': 'application/json' } });
    }
    if (request.headers.get('upgrade') !== 'websocket') return new Response('expected websocket', { status: 426 });
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].send(JSON.stringify({ type: 'windows', turnId: 'none', windows: this.windows() }));
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(_socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') return;
    const frame = decodeClient(message);
    if (Option.isNone(frame)) return;
    const value = frame.value;
    if (value.type === 'turn') this.ctx.waitUntil(Effect.runPromise(this.runTurn(value)));
    if (value.type === 'cancel') await Effect.runPromise(this.cancel(value.turnId));
    if (value.type === 'window_closed') this.saveWindows(this.windows().filter((entry) => entry.id !== value.id));
    if (value.type === 'mcp_result') this.pendingCalls.get(value.callId)?.({ ok: value.ok, text: value.text });
  }
}
