import type { Provider } from '@earendil-works/pi-ai';
import { anthropicMessagesApi } from '@earendil-works/pi-ai/api/anthropic-messages.lazy';
import { createProvider } from '@earendil-works/pi-ai/models';
import { anthropicProvider } from '@earendil-works/pi-ai/providers/anthropic';
import * as Effect from 'effect/Effect';
import * as Option from 'effect/Option';
import * as Schema from 'effect/Schema';

const ANSWERED_BY_BINDING = 'answered-in-process-by-the-ai-binding';

const CREDENTIAL_NAMES = new Set(['CLOUDFLARE_API_KEY', 'CLOUDFLARE_ACCOUNT_ID']);

const CHAT_COMPLETIONS = /^https:\/\/api\.cloudflare\.com\/.*\/ai\/v1\/chat\/completions$/;

export const bindingAuthContext = {
  env: async (name: string): Promise<string | undefined> => (CREDENTIAL_NAMES.has(name) ? ANSWERED_BY_BINDING : undefined),
  fileExists: async (): Promise<boolean> => false,
};

const ChatRequest = Schema.StructWithRest(Schema.Struct({ model: Schema.String }), [Schema.Record(Schema.String, Schema.Json)]);

const decodeChatRequest = Schema.decodeUnknownEffect(Schema.fromJsonString(ChatRequest));

class BindingFailed extends Schema.TaggedError<BindingFailed>()('BindingFailed', { cause: Schema.Defect() }) {}

type AiRun = (model: string, inputs: Readonly<Record<string, Schema.Json>>) => Promise<ReadableStream | AiModels[keyof AiModels]['postProcessedOutputs']>;

const answer = (run: AiRun, request: Request) =>
  Effect.tryPromise({ try: () => request.text(), catch: (cause) => new BindingFailed({ cause }) }).pipe(
    Effect.flatMap(decodeChatRequest),
    Effect.flatMap(({ model, ...inputs }) => Effect.tryPromise({ try: () => run(model, inputs), catch: (cause) => new BindingFailed({ cause }) })),
    Effect.map((result) =>
      result instanceof ReadableStream ? new Response(result, { headers: { 'content-type': 'text/event-stream' } }) : Response.json(result),
    ),
    Effect.catch((error) => Effect.succeed(Response.json({ error: { message: String(error) } }, { status: 502 }))),
  );

const urlOf = (input: RequestInfo | URL): string => (input instanceof Request ? input.url : String(input));

let bridge: Option.Option<{ run: AiRun }> = Option.none();

export const routeWorkersAIThroughBinding = (ai: Ai, gateway: string): void => {
  const run: AiRun = (model, inputs) => ai.run(model, inputs, { gateway: { id: gateway } });
  if (Option.isSome(bridge)) {
    bridge.value.run = run;
    return;
  }
  const current = { run };
  const original = globalThis.fetch.bind(globalThis);
  bridge = Option.some(current);
  globalThis.fetch = (input, init) =>
    CHAT_COMPLETIONS.test(urlOf(input)) ? Effect.runPromise(answer(current.run, new Request(input, init))) : original(input, init);
};

export const GATEWAY_PROVIDER = 't2t-opencode';

export type GatewayEnv = { readonly LLM_GATEWAY_URL: string; readonly LLM_GATEWAY_TOKEN: string };

const anthropicBase = (url: string) => url.replace(/\/openai\/?$/, '/anthropic').replace(/\/$/, '');

export const gatewayProvider = (env: GatewayEnv): Provider => {
  const baseUrl = anthropicBase(env.LLM_GATEWAY_URL);
  const headers = {
    'cf-access-token': env.LLM_GATEWAY_TOKEN,
    authorization: `Bearer ${env.LLM_GATEWAY_TOKEN}`,
    'X-Requested-With': 'xmlhttprequest',
  };
  const wanted = new Set(['claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5']);
  return createProvider({
    id: GATEWAY_PROVIDER,
    name: 'OpenCode Cloudflare gateway',
    baseUrl,
    auth: { apiKey: { name: 'opencode gateway', resolve: async () => ({ auth: { headers }, source: 'gateway' }) } },
    models: anthropicProvider()
      .getModels()
      .filter((model) => wanted.has(model.id))
      .map((model) => ({ ...model, provider: GATEWAY_PROVIDER, baseUrl })),
    api: anthropicMessagesApi(),
  });
};
