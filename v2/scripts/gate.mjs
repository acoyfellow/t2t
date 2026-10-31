import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const tmp = join(root, '.tmp', 'gate');
mkdirSync(tmp, { recursive: true });
const key = readFileSync(join(root, '.secrets', 'key'), 'utf8').trim();
const agent = process.env.T2T_URL ?? 'https://t2t-v2.customer0.dev';
const shell = 'http://127.0.0.1:5198';
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const results = [];
const record = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name} · ${detail}`);
};
const getJson = async (url, init) => (await fetch(url, init)).json();
const state = () => getJson(`${shell}/state`);
const osa = (script) => execFileSync('osascript', ['-e', script], { encoding: 'utf8' }).trim();

const signature = () => {
  const out = execFileSync('codesign', ['-d', '-r-', join(root, 'dist', 'T2T.app')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return out.trim().split('\n').at(-1);
};

const checkSignature = () => {
  const before = signature();
  execFileSync(join(root, 'scripts', 'build-shell.sh'), { stdio: 'ignore' });
  const after = signature();
  const stable = before === after && before.includes('identifier "dev.coey.t2t"') && before.includes('certificate leaf = H"');
  record('stable signature across rebuilds', stable, stable ? before.replace('designated => ', '') : `${before} vs ${after}`);
};

const checkDictation = async () => {
  const s = await state();
  if (!s.accessibility) return record('Fn dictation pastes into the focused field', false, 'Accessibility not granted to dev.coey.t2t');
  const phrase = `t2t gate ${Date.now()}`;
  osa('tell application "TextEdit" to activate');
  osa('tell application "TextEdit" to make new document');
  await pause(800);
  await fetch(`${shell}/hold?mode=dictate&seconds=0.3&text=${encodeURIComponent(phrase)}`);
  await pause(2500);
  const body = osa('tell application "TextEdit" to get text of front document');
  osa('tell application "TextEdit" to close front document saving no');
  record('Fn dictation pastes into the focused field', body.includes(phrase), `TextEdit has "${body.slice(0, 60)}"`);
};

const checkAgentTurnAndDraw = async () => {
  const s = await state();
  const marker = `gate-${Date.now()}`;
  const text = `Draw a red box at x 200, y 200, width 500, height 300 labelled ${marker}, then say done.`;
  const blank = join(tmp, 'before.png');
  const after = join(tmp, 'after.png');
  if (s.screenRecording) execFileSync('screencapture', ['-x', '-R200,200,500,300', blank]);
  await fetch(`${shell}/hold?mode=agent&seconds=0.3&text=${encodeURIComponent(text)}`);
  let turn;
  for (let i = 0; i < 25 && turn === undefined; i++) {
    await pause(2000);
    const turns = await getJson(`${agent}/agent/turns`, { headers: { authorization: `Bearer ${key}` } });
    turn = turns.find((t) => t.input.includes(marker) && t.status !== 'running');
  }
  const recorded = turn !== undefined && turn.status === 'done' && (turn.reply ?? '').length > 0;
  record('agent turn recorded in the Durable Object with a final reply', recorded, turn ? `${turn.status} "${turn.reply}" tools=${turn.tools.join(',')} $${turn.usd.toFixed(5)}` : 'no record');
  const drew = turn !== undefined && turn.draws.length > 0;
  if (!s.screenRecording) {
    record('draw event shows on the overlay (screenshot diff)', false, `agent drew ${turn?.draws.length ?? 0} shape(s); Screen Recording not granted, so the overlay cannot be captured`);
    return;
  }
  await pause(1500);
  execFileSync('screencapture', ['-x', '-R200,200,500,300', after]);
  const a = readFileSync(blank);
  const b = readFileSync(after);
  let differing = 0;
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) if (a[i] !== b[i]) differing++;
  const changed = drew && differing > length * 0.01;
  record('draw event shows on the overlay (screenshot diff)', changed, `${turn?.draws.length ?? 0} shape(s), ${differing} of ${length} bytes differ`);
};

const shellUp = await state().then(() => true, () => false);
if (!shellUp) {
  console.log('FAIL shell not running at 127.0.0.1:5198 (open dist/T2T.app)');
  process.exit(1);
}
checkSignature();
execFileSync('pkill', ['-f', 'T2T.app/Contents/MacOS/T2T']);
execFileSync('open', [join(root, 'dist', 'T2T.app')]);
for (let i = 0; i < 20 && !(await state().then(() => true, () => false)); i++) await pause(500);
await pause(2500);
await checkDictation();
await checkAgentTurnAndDraw();
writeFileSync(join(tmp, 'result.json'), JSON.stringify({ at: new Date().toISOString(), results }, null, 1));
const passed = results.filter((r) => r.ok).length;
console.log(`${passed}/${results.length} checks pass`);
process.exit(passed === results.length && existsSync(join(tmp, 'result.json')) ? 0 : 1);
