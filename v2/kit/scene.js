const PALETTES = {
  night: { bg: '#0a0a0a', panel: '#141414', ink: '#f4f4f5', muted: '#71717a', faint: '#27272a', accent: '#00ffa3', second: '#c27aff' },
  paper: { bg: '#f4f1ea', panel: '#ebe6db', ink: '#1b1a17', muted: '#8a857a', faint: '#d8d2c4', accent: '#9b2c1f', second: '#1f5f9b' },
};

const SVG = 'http://www.w3.org/2000/svg';
const el = (name, attrs = {}, parent) => {
  const node = document.createElementNS(SVG, name);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  if (parent) parent.appendChild(node);
  return node;
};

const centerOf = (box) => ({ x: box.x + box.w / 2, y: box.y + box.h / 2 });

const anchor = (box, toward) => {
  const c = centerOf(box);
  const dx = toward.x - c.x;
  const dy = toward.y - c.y;
  if (Math.abs(dx) * box.h > Math.abs(dy) * box.w) return { x: dx > 0 ? box.x + box.w : box.x, y: c.y };
  return { x: c.x, y: dy > 0 ? box.y + box.h : box.y };
};

const wirePath = (from, to, route) => {
  if (route === 'below') {
    const a = { x: from.x + from.w / 2, y: from.y + from.h };
    const b = { x: to.x + to.w / 2, y: to.y + to.h };
    const y = Math.max(a.y, b.y) + 28;
    return `M${a.x} ${a.y} L${a.x} ${y} L${b.x} ${y} L${b.x} ${b.y}`;
  }
  const a = anchor(from, centerOf(to));
  const b = anchor(to, centerOf(from));
  const horizontal = Math.abs(b.x - a.x) >= Math.abs(b.y - a.y);
  if (horizontal) {
    const mx = (a.x + b.x) / 2;
    return `M${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`;
  }
  const my = (a.y + b.y) / 2;
  return `M${a.x} ${a.y} C ${a.x} ${my}, ${b.x} ${my}, ${b.x} ${b.y}`;
};

export function play(scene, root = document.body) {
  const p = PALETTES[scene.palette ?? 'night'];
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.documentElement.style.cssText = `--bg:${p.bg};--panel:${p.panel};--ink:${p.ink};--muted:${p.muted};--faint:${p.faint};--accent:${p.accent};--second:${p.second}`;

  root.innerHTML = `
    <main class="kit">
      <header>
        <h1></h1>
        <p class="sub"></p>
        <ol class="steps"></ol>
      </header>
      <figure class="stage"><svg viewBox="0 0 ${scene.width ?? 1100} ${scene.height ?? 520}" role="img"></svg></figure>
      <p class="caption"></p>
    </main>`;
  root.querySelector('h1').textContent = scene.title;
  root.querySelector('.sub').textContent = scene.subtitle ?? '';
  const stepsList = root.querySelector('.steps');
  const caption = root.querySelector('.caption');
  const svg = root.querySelector('svg');

  const stepItems = scene.steps.map((step, index) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="n">${String(index + 1).padStart(2, '0')}</span><span class="t"></span>`;
    li.querySelector('.t').textContent = step.label;
    stepsList.appendChild(li);
    return li;
  });

  for (const region of scene.regions ?? []) {
    const g = el('g', { class: 'region' }, svg);
    el('rect', { x: region.x, y: region.y, width: region.w, height: region.h, 'stroke-dasharray': '4 4' }, g);
    el('text', { x: region.x + 14, y: region.y + 24, class: 'region-label' }, g).textContent = region.label;
  }

  const boxes = new Map(scene.boxes.map((box) => [box.id, box]));
  const wireNodes = new Map();
  for (const wire of scene.wires ?? []) {
    const from = boxes.get(wire.from);
    const to = boxes.get(wire.to);
    const d = wirePath(from, to, wire.route);
    const g = el('g', { class: 'wire' }, svg);
    el('path', { d, class: 'track' }, g);
    const live = el('path', { d, class: 'live', pathLength: 1 }, g);
    let label;
    if (wire.label) {
      const mid = wire.route === 'below'
        ? { x: (centerOf(from).x + centerOf(to).x) / 2, y: Math.max(from.y + from.h, to.y + to.h) + 28 }
        : { x: (centerOf(from).x + centerOf(to).x) / 2, y: (centerOf(from).y + centerOf(to).y) / 2 };
      label = el('text', { x: mid.x, y: mid.y - 10, class: 'wire-label', 'text-anchor': 'middle' }, g);
      label.textContent = wire.label;
    }
    wireNodes.set(wire.id ?? `${wire.from}>${wire.to}`, { g, live, d, label });
  }

  const boxNodes = new Map();
  for (const box of scene.boxes) {
    const g = el('g', { class: 'box' }, svg);
    el('rect', { x: box.x, y: box.y, width: box.w, height: box.h }, g);
    if (box.kicker) el('text', { x: box.x + 14, y: box.y + 22, class: 'kicker' }, g).textContent = box.kicker;
    el('text', { x: box.x + 14, y: box.y + (box.kicker ? 48 : box.h / 2 + 7), class: 'title' }, g).textContent = box.label;
    boxNodes.set(box.id, g);
  }

  const dots = el('g', { class: 'dots' }, svg);

  const show = (index) => {
    const step = scene.steps[index];
    stepItems.forEach((li, i) => li.classList.toggle('on', i === index));
    stepItems.forEach((li, i) => li.classList.toggle('done', i < index));
    caption.textContent = step.caption ?? step.label;
    caption.classList.remove('in');
    void caption.offsetWidth;
    caption.classList.add('in');

    const lit = new Set(step.lit ?? []);
    const seen = new Set(scene.steps.slice(0, index + 1).flatMap((s) => s.lit ?? []));
    for (const [id, g] of boxNodes) {
      g.classList.toggle('lit', lit.has(id));
      g.classList.toggle('seen', seen.has(id) && !lit.has(id));
    }

    const flowing = new Set(step.flow ?? []);
    dots.replaceChildren();
    let delay = 0;
    for (const [id, wire] of wireNodes) {
      const on = flowing.has(id);
      wire.g.classList.toggle('on', on);
      if (!on) continue;
      wire.live.style.transitionDelay = `${delay}ms`;
      if (!still) {
        for (let k = 0; k < 2; k += 1) {
          const dot = el('circle', { r: 5, class: 'dot' }, dots);
          const at = svg.getCurrentTime();
          el('animateMotion', { dur: '1.6s', begin: `${at + delay / 1000 + k * 0.8}s`, repeatCount: 'indefinite', path: wire.d }, dot);
        }
      }
      delay += 160;
    }
  };

  if (still) {
    show(scene.steps.length - 1);
    return;
  }
  const durations = scene.steps.map((step, i) => step.ms ?? (i === scene.steps.length - 1 ? 3600 : 2200));
  window.STEPS = durations;
  const loop = durations.reduce((a, b) => a + b, 0);
  const stepAt = (t) => {
    let left = t % loop;
    for (let i = 0; i < durations.length; i += 1) {
      if (left < durations[i]) return i;
      left -= durations[i];
    }
    return 0;
  };
  let shown = -1;
  const render = (t) => {
    const index = stepAt(t);
    if (index !== shown) {
      shown = index;
      show(index);
    }
  };
  let manual = 0;
  window.__kitTick = (dt) => {
    if (manual === 0) {
      svg.pauseAnimations();
      shown = -1;
    }
    manual += dt;
    render(manual);
    for (const animation of document.getAnimations()) {
      animation.pause();
      animation.currentTime = (animation.currentTime ?? 0) + dt;
    }
    svg.setCurrentTime(manual / 1000);
    return manual;
  };
  const started = performance.now();
  const clock = setInterval(() => {
    if (manual > 0) return clearInterval(clock);
    render(performance.now() - started);
  }, 50);
  render(0);
}

export const css = `
@import url('https://fonts.googleapis.com/css2?family=Google+Sans+Code:wght@400;700&display=swap');
* { box-sizing: border-box; margin: 0; }
html, body { height: 100%; background: var(--bg); color: var(--ink); overflow: hidden; }
.kit { height: 100%; display: grid; grid-template-rows: auto 1fr auto; gap: 20px; padding: 32px 40px 28px; font: 14px/1.6 'Google Sans Code', ui-monospace, monospace; }
h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.01em; }
.sub { color: var(--muted); margin-top: 4px; }
.steps { list-style: none; padding: 0; margin-top: 20px; display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; gap: 12px; }
.steps li { border-top: 2px solid var(--faint); padding-top: 10px; color: var(--muted); transition: color .4s, border-color .4s; }
.steps li .n { display: block; font-size: 12px; }
.steps li.done { border-color: var(--muted); }
.steps li.on { border-color: var(--accent); color: var(--ink); }
.steps li.on .n { color: var(--accent); }
.stage { border: 1px solid var(--faint); background: var(--panel); min-height: 0; display: flex; align-items: center; justify-content: center; padding: 16px; }
.stage svg { width: 100%; height: 100%; font-family: 'Google Sans Code', ui-monospace, monospace; }
.region rect { fill: none; stroke: var(--faint); stroke-width: 1.4; }
.region-label { fill: var(--muted); font-size: 14px; }
.box rect { fill: var(--bg); stroke: var(--faint); stroke-width: 1.4; transition: stroke .45s, fill .45s; }
.box .kicker { fill: var(--muted); font-size: 13px; transition: fill .45s; }
.box .title { fill: var(--muted); font-size: 20px; font-weight: 700; transition: fill .45s; }
.box.seen rect { stroke: var(--muted); }
.box.seen .title { fill: var(--ink); }
.box.lit rect { stroke: var(--accent); stroke-width: 2; }
.box.lit .title { fill: var(--ink); }
.box.lit .kicker { fill: var(--accent); }
.wire .track { fill: none; stroke: var(--faint); stroke-width: 1.4; }
.wire .live { fill: none; stroke: var(--accent); stroke-width: 2; stroke-dasharray: 1; stroke-dashoffset: 1; transition: stroke-dashoffset .7s cubic-bezier(.3,.7,.2,1); }
.wire.on .live { stroke-dashoffset: 0; }
.wire-label { fill: var(--muted); font-size: 13px; transition: fill .4s; }
.wire.on .wire-label { fill: var(--accent); }
.dot { fill: var(--accent); }
.caption { font-size: 18px; min-height: 1.6em; opacity: 0; transform: translateY(6px); }
.caption.in { animation: rise .5s cubic-bezier(.3,.7,.2,1) forwards; }
@keyframes rise { to { opacity: 1; transform: none; } }
`;
