import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const port = Number(process.env.T2T_MCP_PORT ?? 5196);
const key = process.env.T2T_KEY ?? '';
const configPath = process.env.T2T_MCP_CONFIG ?? join(homedir(), '.pi/agent/mcp.json');
const connectTimeoutMs = 20000;
const callTimeoutMs = 60000;

const clients = new Map();

const readServers = () => JSON.parse(readFileSync(configPath, 'utf8')).mcpServers ?? {};

const withTimeout = (promise, ms, what) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`${what} timed out after ${ms / 1000}s`)), ms))]);

const transportFor = (definition) => {
  if (definition.url) {
    const headers = definition.headers ?? {};
    return new StreamableHTTPClientTransport(new URL(definition.url), { requestInit: { headers } });
  }
  return new StdioClientTransport({
    command: definition.command,
    args: definition.args ?? [],
    env: { ...getDefaultEnvironment(), PATH: process.env.PATH, HOME: homedir(), ...(definition.env ?? {}) },
    cwd: definition.cwd,
    stderr: 'pipe',
  });
};

const connect = async (name) => {
  const existing = clients.get(name);
  if (existing) return existing;
  const definition = readServers()[name];
  if (!definition) throw new Error(`no MCP server named ${name} in ${configPath}`);
  const pending = (async () => {
    const client = new Client({ name: 't2t', version: '2.0.0' });
    const transport = transportFor(definition);
    transport.onclose = () => clients.delete(name);
    await withTimeout(client.connect(transport), connectTimeoutMs, `connecting to ${name}`);
    const { tools } = await withTimeout(client.listTools(), connectTimeoutMs, `listing ${name} tools`);
    return { client, tools };
  })();
  clients.set(name, pending);
  pending.catch(() => clients.delete(name));
  return pending;
};

const toolsFor = async (names) => {
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
