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
const MCP_CALL_TIMEOUT_MS = 75_000;

const PROMPT = [
  'You are the voice assistant inside t2t on a Mac. The user speaks, you answer briefly.',
  'You can draw on top of the user screen with the draw tool. Coordinates are screen points from the top-left corner.',
  'Use draw to point at things, show layouts, or sketch an answer. Use clear_screen to remove your drawings.',
  'Answer in one or two short spoken sentences. No markdown.',
  'The user may have local MCP tools on their Mac. They are listed with each request. Call mcp_describe to read a tool input schema, then mcp_call to run it.',
  'Only call MCP tools the request needs. Say plainly what a tool returned. If a tool needs a login, tell the user which command to run.',
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

type Active = { turnId: string; draws: DrawShape[]; tools: string[] };

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
        description: 'Read the current HTML of one of your windows, to edit it with window_open.',
        parameters: Type.Object({ id: Type.String() }),
        replay: 'safe',
        execute: async ({ id }) => {
          const found = this.windows().find((entry) => entry.id === id);
          return text(found ? found.html : `No window ${id}.`);
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
          return text(`Closed window ${id}.`);
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
          yield* pi('configure', () => conversation.configure({ model: { provider: provider.id, modelId: this.env.MODEL } }, CONTEXT));
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
      const active: Active = { turnId: request.turnId, draws: [], tools: [] };
      this.active = Option.some(active);
      this.saveRecord({ turnId: request.turnId, startedAt: started, input: request.text, status: 'running', tools: [], draws: [], usd: 0 });
      const { harness, conversation } = yield* pi('open', () => this.open());
      const seen: AgentEvent[] = [];
      let streamedSoFar = '';
      let broadcastLength = 0;
      const stream = yield* pi('watch', () => watchEvents(harness, conversation.id, CONTEXT));
      stream.start(async (events) => {
        seen.push(...events);
        for (const event of events) {
          if (event.type === 'tool_execution_start') {
            active.tools.push(event.toolName);
            this.broadcast({ type: 'tool', turnId: request.turnId, name: event.toolName });
          }
          if (event.type === 'message_end') {
            streamedSoFar = '';
            broadcastLength = 0;
            continue;
          }
          const known = streamedTextOf(event);
          if (known !== undefined && known.length > broadcastLength && known.startsWith(streamedSoFar.slice(0, broadcastLength))) {
            this.broadcast({ type: 'text', turnId: request.turnId, text: known.slice(broadcastLength) });
            streamedSoFar = known;
            broadcastLength = known.length;
          } else if (event.type === 'message_update') {
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
      const submission = yield* pi('submit', () =>
        conversation.submit({ type: 'input', content: `${request.text}${screen}${toolList}`, requestId: request.turnId }, CONTEXT),
      );
      const settled = yield* pi('wait', () => submission.wait(CONTEXT));
      yield* Effect.promise(() => stream.stop());
      const usd = costOf(seen);
      const reply = Option.getOrElse(replyOf(seen), () => '');
      if (settled.status !== 'done') {
        return yield* Effect.fail(new HarnessFailed({ step: 'settle', reason: `submission ${settled.status}` }));
      }
      this.saveRecord({
        turnId: request.turnId,
        startedAt: started,
        endedAt: Date.now(),
        input: request.text,
        status: 'done',
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
            status: 'failed',
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
          if (record !== undefined) this.saveRecord({ ...record, status: 'cancelled', endedAt: Date.now() });
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
