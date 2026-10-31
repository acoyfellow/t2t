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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/health') return Response.json({ ok: true });
    if (!timingSafeEqual(keyOf(request, url), env.T2T_KEY)) return new Response('unauthorized', { status: 401 });
    if (url.pathname === '/agent' || url.pathname === '/agent/turns' || url.pathname === '/agent/gateway-token') {
      return env.AGENT.get(env.AGENT.idFromName('me')).fetch(request);
    }
    return new Response('not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
