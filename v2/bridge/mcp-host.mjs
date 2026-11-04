import { createServer } from 'node:http';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { LoggingMessageNotificationSchema } from '@modelcontextprotocol/sdk/types.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const port = Number(process.env.T2T_MCP_PORT ?? 5196);
const key = process.env.T2T_KEY ?? '';
const configPath = process.env.T2T_MCP_CONFIG ?? join(homedir(), '.pi/agent/mcp.json');
const connectTimeoutMs = 20000;
const callTimeoutMs = 60000;

const clients = new Map();
const actionEvents = [];
let actionSequence = 0;
const rememberAction = (server, data) => {
  actionSequence += 1;
  actionEvents.push({ seq: actionSequence, server, at: Date.now(), ...data });
  if (actionEvents.length > 200) actionEvents.splice(0, actionEvents.length - 200);
};
const status = new Map();
const parked = new Set();

const setStatus = (name, next) => status.set(name, { ...(status.get(name) ?? {}), ...next, at: new Date().toISOString() });

const summary = (name) => {
  const entry = status.get(name) ?? { state: 'idle' };
  return { server: name, state: parked.has(name) ? 'disconnected' : entry.state, error: entry.error, tools: entry.tools ?? [], at: entry.at };
};

const localConfigPath = join(import.meta.dirname, 'mcp.local.json');
const readConfig = (path) => {
  try {
    return JSON.parse(readFileSync(path, 'utf8')).mcpServers ?? {};
  } catch {
    return {};
  }
};
const readServers = () => ({ ...readConfig(configPath), ...readConfig(localConfigPath) });

const withTimeout = (promise, ms, what) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`${what} timed out after ${ms / 1000}s`)), ms))]);

const certificateNames = ['NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'];
const certificateEnvironment = () => Object.fromEntries(certificateNames.filter((name) => process.env[name]).map((name) => [name, process.env[name]]));

const resolveValue = (value) =>
  typeof value === 'string' && value.startsWith('!') ? execSync(value.slice(1), { encoding: 'utf8', timeout: 10000 }).trim() : value;
const resolveHeaders = (headers) => Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, resolveValue(value)]));

const transportFor = (definition) => {
  if (definition.url) {
    const headers = resolveHeaders(definition.headers ?? {});
    return new StreamableHTTPClientTransport(new URL(definition.url), { requestInit: { headers } });
  }
  return new StdioClientTransport({
    command: definition.command,
    args: definition.args ?? [],
    env: { ...getDefaultEnvironment(), ...certificateEnvironment(), PATH: process.env.PATH, HOME: homedir(), ...(definition.env ?? {}) },
    cwd: definition.cwd,
    stderr: 'pipe',
  });
};

const connect = async (name) => {
  if (parked.has(name)) throw new Error(`${name} is disconnected in t2t settings`);
  const existing = clients.get(name);
  if (existing) return existing;
  const definition = readServers()[name];
  if (!definition) throw new Error(`no MCP server named ${name} in ${configPath}`);
  const pending = (async () => {
    const client = new Client({ name: 't2t', version: '2.0.0' });
    client.setNotificationHandler(LoggingMessageNotificationSchema, (notification) => {
      if (['hand.action', 'do.action'].includes(notification.params.logger) && typeof notification.params.data === 'object') rememberAction(name, notification.params.data);
    });
    const transport = transportFor(definition);
    transport.onclose = () => {
      clients.delete(name);
      if (status.get(name)?.state === 'connected') setStatus(name, { state: 'error', error: 'connection closed' });
    };
    await withTimeout(client.connect(transport), connectTimeoutMs, `connecting to ${name}`);
    const { tools } = await withTimeout(client.listTools(), connectTimeoutMs, `listing ${name} tools`);
    return { client, tools };
  })();
  clients.set(name, pending);
  setStatus(name, { state: 'connecting', error: undefined });
  pending.then(
    ({ tools }) => setStatus(name, { state: 'connected', error: undefined, tools: tools.map((tool) => ({ name: tool.name, description: tool.description ?? '' })) }),
    (error) => {
      clients.delete(name);
      setStatus(name, { state: 'error', error: String(error?.message ?? error), tools: [] });
    },
  );
  return pending;
};

const toolsFor = async (names) => {
  names = names.filter((name) => !parked.has(name));
  const settled = await Promise.allSettled(names.map(async (name) => ({ name, ...(await connect(name)) })));
  return settled.map((result, index) =>
    result.status === 'fulfilled'
      ? {
          server: names[index],
          ok: true,
          tools: result.value.tools.map((tool) => ({ name: tool.name, description: tool.description ?? '', inputSchema: tool.inputSchema })),
        }
      : { server: names[index], ok: false, error: String(result.reason?.message ?? result.reason) },
  );
};

const disconnect = async (name) => {
  const pending = clients.get(name);
  clients.delete(name);
  if (pending) await pending.then(({ client }) => client.close(), () => undefined);
};

const refresh = async (name) => {
  parked.delete(name);
  await disconnect(name);
  status.delete(name);
  await connect(name).catch(() => undefined);
  return summary(name);
};

const park = async (name) => {
  parked.add(name);
  await disconnect(name);
  setStatus(name, { state: 'disconnected', error: undefined });
  return summary(name);
};

const statusFor = (names, warm) => {
  if (warm) for (const name of names) if (!parked.has(name) && !clients.has(name) && status.get(name)?.state !== 'error') connect(name).catch(() => undefined);
  return names.map(summary);
};

const flatten = (content) =>
  (content ?? [])
    .map((block) => (block.type === 'text' ? block.text : block.type === 'resource' ? (block.resource?.text ?? '') : `[${block.type}]`))
    .join('\n');

const call = async (server, tool, args) => {
  const { client } = await connect(server);
  const result = await withTimeout(client.callTool({ name: tool, arguments: args ?? {} }), callTimeoutMs, `${server}.${tool}`);
  return { ok: !result.isError, text: flatten(result.content) || JSON.stringify(result.structuredContent ?? {}) };
};

const readBody = (request) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });

const reply = (response, status, body) => {
  response.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type' });
  response.end(JSON.stringify(body));
};

createServer(async (request, response) => {
  if (request.method === 'OPTIONS') return reply(response, 204, {});
  if (request.headers.authorization !== `Bearer ${key}`) return reply(response, 401, { error: 'unauthorized' });
  try {
    const body = request.method === 'POST' ? JSON.parse((await readBody(request)) || '{}') : {};
    if (request.url === '/health') return reply(response, 200, { ok: true, connected: [...clients.keys()] });
    if (request.url === '/tools') return reply(response, 200, { servers: await toolsFor(body.servers ?? []) });
    if (request.url?.startsWith('/actions')) {
      const since = Number(new URL(request.url, 'http://x').searchParams.get('since') ?? 0);
      return reply(response, 200, { seq: actionSequence, events: actionEvents.filter((event) => event.seq > since) });
    }
    if (request.url === '/status') return reply(response, 200, { servers: statusFor(body.servers ?? [], body.warm === true) });
    if (request.url === '/refresh') return reply(response, 200, await refresh(body.server));
    if (request.url === '/disconnect') return reply(response, 200, await park(body.server));
    if (request.url === '/connect') return reply(response, 200, await refresh(body.server));
    if (request.url === '/call') return reply(response, 200, await call(body.server, body.tool, body.arguments));
    return reply(response, 404, { error: 'not found' });
  } catch (error) {
    return reply(response, 200, { ok: false, text: `MCP error: ${error?.message ?? error}` });
  }
}).listen(port, '127.0.0.1', () => console.log(`t2t mcp host on 127.0.0.1:${port}`));

const shutdown = async () => {
  await Promise.allSettled([...clients.values()].map(async (pending) => (await pending).client.close()));
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
