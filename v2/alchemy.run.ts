import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as Alchemy from 'alchemy';
import * as Cloudflare from 'alchemy/Cloudflare';
import * as Effect from 'effect/Effect';
import * as Redacted from 'effect/Redacted';
import type { Agent } from './worker/src/agent.ts';

const key = readFileSync(join(import.meta.dirname, '.secrets', 'key'), 'utf8').trim();

export default Alchemy.Stack(
  't2t-v2',
  { providers: Cloudflare.providers(), state: Alchemy.localState() },
  Effect.gen(function* () {
    const worker = yield* Cloudflare.Worker('worker', {
      name: 't2t-v2',
      main: './worker/src/index.ts',
      compatibility: { date: '2026-09-30', flags: ['nodejs_compat'] },
      workersDev: false,
      domain: 't2t-v2.customer0.dev',
      env: {
        AGENT: Cloudflare.DurableObject<Agent>('Agent'),
        AI: Cloudflare.Workers.AI('AI'),
        GATEWAY: 'default',
        MODEL: '@cf/moonshotai/kimi-k2.6',
        T2T_KEY: Redacted.make(key),
      },
    });
    return { url: worker.url };
  }),
);
