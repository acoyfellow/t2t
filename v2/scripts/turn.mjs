import { readFileSync } from 'node:fs';
const key = readFileSync(new URL('../.secrets/key', import.meta.url), 'utf8').trim();
const base = process.env.T2T_URL ?? 'https://t2t-v2.customer0.dev';
const text = process.argv[2] ?? 'Draw a box around the top left corner of my screen, then say done.';
const turnId = crypto.randomUUID();
const ws = new WebSocket(`${base.replace('https', 'wss')}/agent?key=${key}`);
const frames = [];
const timer = setTimeout(() => { console.log('TIMEOUT', JSON.stringify(frames.slice(-3))); process.exit(2); }, Number(process.env.TURN_TIMEOUT ?? 100000));
ws.onopen = () => ws.send(JSON.stringify({ type: 'turn', turnId, text, screen: { width: 1512, height: 982 } }));
ws.onmessage = (event) => {
  const frame = JSON.parse(event.data);
  if (frame.turnId !== turnId && frame.turnId !== 'none') return;
  frames.push(frame);
  if (frame.type !== 'text') console.log(JSON.stringify(frame));
  if (frame.type === 'done' || frame.type === 'failed') { clearTimeout(timer); ws.close(); console.log('TURN', turnId); process.exit(frame.type === 'done' ? 0 : 1); }
};
ws.onerror = (error) => { console.log('ERR', String(error.message ?? error)); process.exit(3); };
