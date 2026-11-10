import type { Provider } from '@earendil-works/pi-ai';
import { anthropicMessagesApi } from '@earendil-works/pi-ai/api/anthropic-messages.lazy';
import { googleGenerativeAIApi } from '@earendil-works/pi-ai/api/google-generative-ai.lazy';
import { openAICompletionsApi } from '@earendil-works/pi-ai/api/openai-completions.lazy';
import { openAIResponsesApi } from '@earendil-works/pi-ai/api/openai-responses.lazy';
import { createProvider } from '@earendil-works/pi-ai/models';
import { OPENCODE_MODELS } from '@earendil-works/pi-ai/providers/opencode.models';
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

export const VOICE_CONTEXT_TOKENS = 64000;
export const GATEWAY_PROVIDER = 't2t-opencode';

export type GatewayEnv = { readonly LLM_GATEWAY_URL: string; readonly LLM_GATEWAY_TOKEN: string };

const anthropicBase = (url: string) => url.replace(/\/openai\/?$/, '/anthropic').replace(/\/$/, '');

export const tokenExpiry = (token: string): number | undefined => {
  const payload = token.split('.')[1];
  if (payload === undefined) return undefined;
  try {
    const claims: unknown = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    const exp = typeof claims === 'object' && claims !== null ? Reflect.get(claims, 'exp') : undefined;
    return typeof exp === 'number' ? exp * 1000 : undefined;
  } catch {
    return undefined;
  }
};

export const gatewayProvider = (env: GatewayEnv, currentToken: () => string): Provider => {
  const baseUrl = anthropicBase(env.LLM_GATEWAY_URL);
  const headers = () => {
    const token = currentToken();
    return { 'cf-access-token': token, authorization: `Bearer ${token}`, 'X-Requested-With': 'xmlhttprequest' };
  };
  return createProvider({
    id: GATEWAY_PROVIDER,
    name: 'OpenCode Cloudflare gateway',
    baseUrl,
    auth: { apiKey: { name: 'opencode gateway', resolve: async () => ({ auth: { headers: headers() }, source: 'gateway' }) } },
    models: Object.values(OPENCODE_MODELS).map((model) => ({ ...model, provider: GATEWAY_PROVIDER, baseUrl, contextWindow: Math.min(model.contextWindow, VOICE_CONTEXT_TOKENS) })),
    api: {
      'anthropic-messages': anthropicMessagesApi(),
      'google-generative-ai': googleGenerativeAIApi(),
      'openai-completions': openAICompletionsApi(),
      'openai-responses': openAIResponsesApi(),
    },
  });
};
