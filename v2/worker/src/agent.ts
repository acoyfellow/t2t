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
  type ServerFrame,
  ServerFrameJson,
  type TurnRecord,
  TurnRecordsJson,
  type TurnRequest,
} from '../../shared/protocol';
import { bindingAuthContext, routeWorkersAIThroughBinding } from './model';

export type AgentEnv = { readonly AI: Ai; readonly MODEL: string; readonly GATEWAY: string };

const CONTEXT = BACKGROUND_CONTEXT;

const RECORD_LIMIT = 200;

const PROMPT = [
  'You are the voice assistant inside t2t on a Mac. The user speaks, you answer briefly.',
  'You can draw on top of the user screen with the draw tool. Coordinates are screen points from the top-left corner.',
  'Use draw to point at things, show layouts, or sketch an answer. Use clear_screen to remove your drawings.',
  'Answer in one or two short spoken sentences. No markdown.',
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

export class Agent extends DurableObject<AgentEnv> {
  private live: Option.Option<Promise<Live>> = Option.none();
  private active: Option.Option<Active> = Option.none();

  constructor(ctx: DurableObjectState, env: AgentEnv) {
    super(ctx, env);
    routeWorkersAIThroughBinding(env.AI, env.GATEWAY);
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

  private tools() {
    return [
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
          const provider = cloudflareWorkersAIProvider();
          models.setProvider(provider);
          const registry = createRegistry();
          registry.install(
            defineExtension({ name: 't2t', sections: [section('preamble', () => PROMPT, { tag: false })], tools: this.tools() }),
          );
          const storage = yield* pi('storage', () => openDurableObjectSqliteStorage(this.ctx.storage));
          const harness = yield* pi('open', async () => Harness.open(storage, { models, registry }, CONTEXT));
          const conversation = yield* pi('root', () =>
            harness.root(CONTEXT, { agent: { model: { provider: provider.id, modelId: this.env.MODEL } } }),
          );
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
      const stream = yield* pi('watch', () => watchEvents(harness, conversation.id, CONTEXT));
      stream.start(async (events) => {
        seen.push(...events);
        for (const event of events) {
          if (event.type === 'tool_execution_start') {
            active.tools.push(event.toolName);
            this.broadcast({ type: 'tool', turnId: request.turnId, name: event.toolName });
          }
          if (event.type === 'message_update') {
            for (const change of event.changes) {
              if (change.type === 'text_delta') this.broadcast({ type: 'text', turnId: request.turnId, text: change.delta });
            }
          }
        }
      });
      const screen = request.screen === undefined ? '' : `\n\n(Screen is ${request.screen.width}x${request.screen.height} points.)`;
      const submission = yield* pi('submit', () =>
        conversation.submit({ type: 'input', content: `${request.text}${screen}`, requestId: request.turnId }, CONTEXT),
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
    if (url.pathname.endsWith('/turns')) {
      return new Response(encodeRecords(this.records().slice().reverse()), { headers: { 'content-type': 'application/json' } });
    }
    if (request.headers.get('upgrade') !== 'websocket') return new Response('expected websocket', { status: 426 });
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(_socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== 'string') return;
    const frame = decodeClient(message);
    if (Option.isNone(frame)) return;
    const value = frame.value;
    if (value.type === 'turn') this.ctx.waitUntil(Effect.runPromise(this.runTurn(value)));
    if (value.type === 'cancel') await Effect.runPromise(this.cancel(value.turnId));
  }
}
