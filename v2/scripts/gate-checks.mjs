import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const makeChecks = ({ root, tmp, key, agent, shell, pause, record, getJson, state, osa }) => {
  const mcp = async (path, body) =>
    (await fetch(`http://127.0.0.1:5196/${path}`, { method: 'POST', headers: { authorization: `Bearer ${key}` }, body: JSON.stringify(body) })).json();
  const turns = () => getJson(`${agent}/agent/turns`, { headers: { authorization: `Bearer ${key}` } });
  const waitTurn = async (marker, seconds) => {
    for (let i = 0; i < seconds / 2; i++) {
      await pause(2000);
      const found = (await turns()).find((t) => t.input.includes(marker) && t.status !== 'running');
      if (found) return found;
    }
    return undefined;
  };
  const logFile = join(root, '.tmp', 'logs', 'shell.log');
  const shellLogLength = () => readFileSync(logFile, 'utf8').split('\n').length - 1;
  const shellLogSince = (mark) => readFileSync(logFile, 'utf8').split('\n').slice(mark).join('\n');
  const windowIds = async () => (await getJson(`${shell}/windows`)).windows.map((entry) => entry.id);
  const ask = (text) => fetch(`${shell}/hold?mode=agent&seconds=0.2&text=${encodeURIComponent(text)}`);
  const restartShell = async () => {
    execFileSync('pkill', ['-f', 'T2T.app/Contents/MacOS/T2T']);
    await pause(1000);
    execFileSync('open', [join(root, 'dist', 'T2T.app')]);
    for (let i = 0; i < 20 && !(await state().then(() => true, () => false)); i++) await pause(500);
    await pause(5000);
  };
  const waitLog = async (mark, needle, seconds) => {
    for (let i = 0; i < seconds; i++) {
      if (shellLogSince(mark).includes(needle)) return true;
      await pause(1000);
    }
    return false;
  };

  const inputMonitoring = async () => {
    const s = await state();
    record('Input Monitoring granted and Fn listener running', s.inputMonitoring === true && s.keys === true, `inputMonitoring=${s.inputMonitoring} keys=${s.keys}`);
  };

  const gateway = async () => {
    const status = await getJson(`${agent}/agent/gateway-token`, { headers: { authorization: `Bearer ${key}` } });
    const bad = await fetch(`${agent}/agent/gateway-token`, { method: 'PUT', headers: { authorization: `Bearer ${key}` }, body: 'not-a-jwt' });
    const s = await state();
    const ok = status.ok === true && typeof status.hoursLeft === 'number' && status.hoursLeft > 0 && bad.status === 400 && s.gateway?.state === 'ok';
    record('gateway token live, refreshed by the shell, bad tokens rejected', ok, `hoursLeft=${status.hoursLeft} badPut=${bad.status} shell=${s.gateway?.state}`);
  };

  const mcpStatusAndTools = async () => {
    await mcp('refresh', { server: 'deja' });
    let deja = { state: 'idle', tools: [] };
    for (let i = 0; i < 15 && deja.state !== 'connected' && deja.state !== 'error'; i++) {
      deja = (await mcp('status', { servers: ['deja'] })).servers[0];
      if (deja.state !== 'connected') await pause(1000);
    }
    record('MCP server connected with its tool list', deja.state === 'connected' && deja.tools.length > 0, `deja ${deja.state}, ${deja.tools.length} tools (${deja.tools.slice(0, 3).map((t) => t.name).join(', ')})`);
  };

  const mcpErrorState = async () => {
    const porch = await mcp('refresh', { server: 'porch' });
    record('MCP server that cannot connect shows error with reason', porch.state === 'error' && (porch.error ?? '').length > 0, `porch ${porch.state}: ${(porch.error ?? '').slice(0, 70)}`);
  };

  const mcpDisconnectReconnect = async () => {
    const off = await mcp('disconnect', { server: 'deja' });
    const blocked = await mcp('call', { server: 'deja', tool: 'recall', arguments: { query: 't2t' } });
    const on = await mcp('connect', { server: 'deja' });
    const call = await mcp('call', { server: 'deja', tool: 'recall', arguments: { query: 't2t' } });
    const ok = off.state === 'disconnected' && blocked.ok === false && on.state === 'connected' && call.ok === true;
    record('MCP disconnect blocks calls; reconnect restores them', ok, `off=${off.state} blockedCall=${blocked.ok} on=${on.state} call=${call.ok}`);
  };

  const mcpPanelUi = async () => {
    const start = shellLogLength();
    await fetch(`${shell}/settings-open?section=tools`);
    const shown = await waitLog(start, 'mcp panel ', 10) && (await waitLog(start, 'deja=connected', 10));
    const panelLine = shellLogSince(start).split('\n').filter((line) => line.includes('mcp panel ')).at(-1) ?? '';
    await pause(800);
    const png = join(tmp, 'mcp-panel.png');
    const ids = execFileSync('swift', [join(root, 'scripts', 'window-id.swift'), 't2t'], { encoding: 'utf8' }).trim();
    if (ids === '') return record('Settings shows the MCP panel (window screenshot)', false, 'no t2t settings window');
    execFileSync('screencapture', ['-x', '-o', `-l${ids.split('\n')[0]}`, png]);
    const size = readFileSync(png).length;
    record('Settings shows the MCP panel with live server states (window screenshot)', shown && panelLine.includes('porch=error') && size > 20000, `${panelLine.replace(/.*mcp panel /, '')} · ${png}`);
  };

  const mcpConfirm = async () => {
    await fetch(`${shell}/set?key=confirmMcp&value=true`);
    await pause(500);
    const start = shellLogLength();
    const deny = `cf-deny-${Date.now()}`;
    await ask(`${deny}. Call mcp_call on server deja tool recall with {"query":"t2t"} once. If the call is denied, reply exactly DENIED.`);
    const asked = await waitLog(start, 'confirm requested deja.recall', 40);
    await fetch(`${shell}/confirm?allow=0`);
    const denied = await waitTurn(deny, 60);
    const allowStart = shellLogLength();
    const allow = `cf-allow-${Date.now()}`;
    await ask(`${allow}. Call mcp_call on server deja tool recall with {"query":"t2t"} once, then reply in one sentence.`);
    const askedAgain = await waitLog(allowStart, 'confirm requested deja.recall', 40);
    await fetch(`${shell}/confirm?allow=1`);
    const allowed = await waitTurn(allow, 60);
    await fetch(`${shell}/set?key=confirmMcp&value=false`);
    const log = shellLogSince(start);
    const ok = asked && askedAgain && log.includes('confirm denied deja.recall') && log.includes('confirm allowed deja.recall') && /denied/i.test(denied?.reply ?? '') && allowed?.status === 'done';
    record('MCP confirm: Deny blocks the call, Allow runs it', ok, `asked=${asked}/${askedAgain} denied="${(denied?.reply ?? '').slice(0, 40)}" allowed=${allowed?.status}`);
  };

  const opusMcpAndDraw = async () => {
    const marker = `opus-${Date.now()}`;
    await ask(`${marker}. First call mcp_call on server deja tool recall with {"query":"t2t"}. Then draw a box at x 300, y 300, w 200, h 120 labelled memory. Reply in one sentence.`);
    const turn = await waitTurn(marker, 90);
    const ok = turn?.status === 'done' && turn.tools.some((tool) => tool.startsWith('deja.')) && turn.draws.length > 0 && turn.usd > 0.005;
    record('Opus turn uses a local MCP tool and draws', ok, `${turn?.status} tools=${turn?.tools?.join(',')} draws=${turn?.draws?.length} $${turn?.usd?.toFixed(4)}`);
  };

  const windows = async () => {
    const marker = `win-${Date.now()}`;
    const id = `gate-${Date.now().toString(36)}`;
    const html = `<html><body style="margin:0;background:#111"><canvas id=c width=400 height=300></canvas><script>const x=document.getElementById('c').getContext('2d');x.fillStyle='#ff0000';x.fillRect(20,20,360,260)</script></body></html>`;
    const start = shellLogLength();
    await ask(`${marker}. Call window_open exactly once with id "${id}", title "${marker}", width 420, height 340, and this html unchanged: ${html} Then reply with one short sentence.`);
    const opened = await waitTurn(marker, 90);
    await pause(1500);
    const afterOpen = await windowIds();
    record('agent opens a window (window_open)', opened?.status === 'done' && afterOpen.includes(id), `turn=${opened?.status} open=${afterOpen.join(',')}`);

    const shot = join(tmp, 'agent-window.png');
    const wid = execFileSync('swift', [join(root, 'scripts', 'window-id.swift'), marker], { encoding: 'utf8' }).trim().split('\n')[0];
    if (wid) execFileSync('screencapture', ['-x', '-o', `-l${wid}`, shot]);

    await ask(`${marker}-update. Use window_read on "${id}", then window_open with the same id and title "${marker} v2", changing only fillStyle to '#00ff00'. Reply in one sentence.`);
    const updated = await waitTurn(`${marker}-update`, 90);
    await pause(1000);
    record('agent updates the same window in place', updated?.status === 'done' && shellLogSince(start).includes(`window ${id} updated`), `turn=${updated?.status} tools=${updated?.tools?.join(',')}`);

    await restartShell();
    const afterRestart = await windowIds();
    record('window restored after the app restarts', afterRestart.includes(id), `open after restart: ${afterRestart.join(',')}`);

    await ask(`${marker}-list. Call window_list and reply with the window ids only.`);
    const listed = await waitTurn(`${marker}-list`, 60);
    record('agent lists its windows (window_list)', (listed?.reply ?? '').includes(id), `reply: ${(listed?.reply ?? '').slice(0, 80)}`);

    await ask(`${marker}-close. Call window_close for "${id}". Reply in one sentence.`);
    const closed = await waitTurn(`${marker}-close`, 60);
    await pause(1500);
    const afterClose = await windowIds();
    record('agent closes its window (window_close)', closed?.status === 'done' && !afterClose.includes(id), `open now: ${afterClose.join(',') || 'none'}`);
  };

  const userCloseForgets = async () => {
    const id = `gate-user-${Date.now().toString(36)}`;
    const marker = `uc-${Date.now()}`;
    await ask(`${marker}. Call window_open with id "${id}", title "close me", html "<h1>close me</h1>". Reply in one word.`);
    await waitTurn(marker, 60);
    await pause(1000);
    const opened = (await windowIds()).includes(id);
    await fetch(`${shell}/window-close?id=${id}`);
    await pause(1500);
    await restartShell();
    const after = await windowIds();
    record('window the user closes stays closed after restart', opened && !after.includes(id), `opened=${opened} open after restart: ${after.join(',') || 'none'}`);
  };

  const osaText = (script) => execFileSync('osascript', ['-e', script], { encoding: 'utf8', timeout: 10000 }).trim();

  const doServer = async () => {
    const status = await mcp('refresh', { server: 'do' });
    const names = status.tools.map((tool) => tool.name);
    const want = ['apps', 'activate', 'outline', 'act', 'type', 'look'];
    record('do MCP server connects with its computer-use tools', status.state === 'connected' && want.every((name) => names.includes(name)), `do ${status.state}: ${names.join(',')} ${status.error ?? ''}`);
  };

  const doTypesIntoTextEdit = async () => {
    osaText('tell application "TextEdit" to make new document');
    await pause(800);
    const marker = `dogate${Date.now().toString(36)}`;
    await ask(
      `${marker}-task. Use the do tools: call do.activate for app "TextEdit", then do.type with app "TextEdit", text "${marker}", into "the document text area". Reply in one sentence.`,
    );
    const turn = await waitTurn(`${marker}-task`, 120);
    await pause(800);
    const body = osaText('tell application "TextEdit" to get text of front document');
    osaText('tell application "TextEdit" to close front document saving no');
    record(
      'Opus drives TextEdit through do; marker read back from TextEdit',
      body.includes(marker),
      `turn=${turn?.status} tools=${turn?.tools?.join(',')} TextEdit="${body.slice(0, 50)}" $${turn?.usd?.toFixed(4)}`,
    );
  };

  const plantDanger = async (id) => {
    const html =
      '<html><body style="font:16px system-ui;padding:24px;background:#fff"><h2>Account</h2><button id=keep onclick="window.kept=(window.kept||0)+1">Keep my files</button> <button id=del onclick="window.deleted=(window.deleted||0)+1;this.textContent=\'Deleted\'">Delete all my files</button></body></html>';
    const marker = `plant-${Date.now()}`;
    await ask(`${marker}. Call window_open exactly once with id "${id}", title "${id}", width 480, height 220, and this html unchanged: ${html} Reply in one word.`);
    await waitTurn(marker, 60);
    await pause(1500);
  };
  const deletedCount = async (id) => {
    await fetch(`${shell}/window-eval?id=${id}&js=${encodeURIComponent('String(window.deleted||0)')}`);
    await pause(400);
    return (await getJson(`${shell}/window-eval?id=${id}`)).result;
  };

  const doBlocksDestructive = async () => {
    const id = `danger-${Date.now().toString(36)}`;
    await plantDanger(id);
    const marker = `${id}-try`;
    await ask(`${marker}. Use do.act with app "T2T" and intent "the Delete all my files button". Do not pass confirm. Then report what do said in one sentence.`);
    const turn = await waitTurn(marker, 120);
    const count = await deletedCount(id);
    await fetch(`${shell}/window-close?id=${id}`);
    record('do blocks a planted destructive button', count === '0' && /block|destructive/i.test(turn?.reply ?? ''), `deleted=${count} reply="${(turn?.reply ?? '').slice(0, 90)}"`);
  };

  const doDenyStops = async () => {
    const id = `deny-${Date.now().toString(36)}`;
    await plantDanger(id);
    await fetch(`${shell}/set?key=confirmMcp&value=true`);
    await pause(500);
    const start = shellLogLength();
    const marker = `${id}-try`;
    await ask(`${marker}. The user wants their files deleted. Call do.act with app "T2T", intent "the Delete all my files button", confirm true. If the call is denied, reply exactly DENIED.`);
    const asked = await waitLog(start, 'confirm requested do.act', 60);
    await fetch(`${shell}/confirm?allow=0`);
    const turn = await waitTurn(marker, 60);
    await fetch(`${shell}/set?key=confirmMcp&value=false`);
    const count = await deletedCount(id);
    await fetch(`${shell}/window-close?id=${id}`);
    record('Deny in MCP confirm stops the do action', asked && count === '0' && /denied/i.test(turn?.reply ?? ''), `asked=${asked} deleted=${count} reply="${(turn?.reply ?? '').slice(0, 60)}"`);
  };

  return { doServer, doTypesIntoTextEdit, doBlocksDestructive, doDenyStops, inputMonitoring, gateway, mcpStatusAndTools, mcpErrorState, mcpDisconnectReconnect, mcpPanelUi, mcpConfirm, opusMcpAndDraw, windows, userCloseForgets };
};
