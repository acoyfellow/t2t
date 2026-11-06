import { Agent, type AgentEnv } from './agent';

export { Agent };

type Env = AgentEnv & { readonly AGENT: DurableObjectNamespace<Agent>; readonly T2T_KEY: string };

const timingSafeEqual = (left: string, right: string): boolean => {
  const encoder = new TextEncoder();
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a, b);
};

const keyOf = (request: Request, url: URL): string =>
  (request.headers.get('authorization') ?? '').replace(/^Bearer /, '') || (url.searchParams.get('key') ?? '');

const LIBRARY_PATH = '/agent/library';
const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, DELETE',
  'access-control-allow-headers': 'authorization',
};

const withCors = (response: Response): Response => {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(CORS_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, headers });
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/health') return Response.json({ ok: true });
    if (url.pathname === LIBRARY_PATH && request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });
    if (url.pathname === LIBRARY_PATH) {
      if (!timingSafeEqual(keyOf(request, url), env.T2T_KEY)) return withCors(new Response('unauthorized', { status: 401 }));
      return withCors(await env.AGENT.get(env.AGENT.idFromName('me')).fetch(request));
    }
    if (!timingSafeEqual(keyOf(request, url), env.T2T_KEY)) return new Response('unauthorized', { status: 401 });
    if (url.pathname === '/agent' || url.pathname === '/agent/turns' || url.pathname === '/agent/gateway-token') {
      return env.AGENT.get(env.AGENT.idFromName('me')).fetch(request);
    }
    return new Response('not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
