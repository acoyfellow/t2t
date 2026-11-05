<script lang="ts" module>
  export const indicatorStyles = [
    { id: 'classic', label: 'Classic bar' },
    { id: 'soundbars', label: 'Sound bars' },
    { id: 'ripples', label: 'Ripples' },
    { id: 'wave', label: 'Waveform' },
    { id: 'aurora', label: 'Aurora' },
    { id: 'orb', label: 'Orb' },
  ] as const;
  export type IndicatorStyle = (typeof indicatorStyles)[number]['id'];
  export type IndicatorPhase = 'idle' | 'listening' | 'thinking' | 'speaking';
</script>

<script lang="ts">
  type Props = {
    style: IndicatorStyle;
    phase: IndicatorPhase;
    mode: 'dictate' | 'agent';
    level: number;
    height?: number;
  };
  let { style, phase, mode, level, height = 160 }: Props = $props();

  let canvas: HTMLCanvasElement | undefined = $state();

  const colorFor = (current: IndicatorPhase, currentMode: 'dictate' | 'agent'): [number, number, number] => {
    if (current === 'listening') return currentMode === 'agent' ? [194, 122, 255] : [0, 255, 163];
    if (current === 'thinking') return currentMode === 'agent' ? [194, 122, 255] : [245, 158, 11];
    return [168, 85, 247];
  };

  const live = {
    get phase() {
      return phase;
    },
    get mode() {
      return mode;
    },
    get level() {
      return level;
    },
    get style() {
      return style;
    },
  };

  $effect(() => {
    if (!canvas) return;
    const context = canvas.getContext('2d');
    if (!context) return;
    const element = canvas;
    let frame = 0;
    let visible = 0;
    let energy = 0;
    let color: [number, number, number] = [194, 122, 255];
    const bars = Array.from({ length: 72 }, () => 0);
    const ripples: { born: number; strength: number }[] = [];
    let lastRipple = 0;

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      element.width = Math.round(element.clientWidth * ratio);
      element.height = Math.round(element.clientHeight * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);

    const targetEnergy = (time: number) => {
      if (live.phase === 'listening') return Math.min(1, live.level * 1.4);
      if (live.phase === 'speaking') return 0.3 + 0.45 * Math.abs(Math.sin(time * 7.3)) * (0.6 + 0.4 * Math.sin(time * 2.1));
      if (live.phase === 'thinking') return 0.18 + 0.08 * Math.sin(time * 3);
      return 0;
    };

    const rgba = (alpha: number) => `rgba(${color[0]},${color[1]},${color[2]},${alpha * visible})`;

    const drawSoundbars = (width: number, base: number, time: number) => {
      const gap = 3;
      const barWidth = (width - gap * (bars.length - 1)) / bars.length;
      for (let index = 0; index < bars.length; index++) {
        const center = 1 - Math.abs(index / (bars.length - 1) - 0.5) * 1.3;
        const travel = live.phase === 'thinking' ? 0.5 + 0.5 * Math.sin(time * 4 - index * 0.35) : 1;
        const jitter = 0.55 + 0.45 * Math.sin(time * (5 + (index % 7)) + index * 1.7);
        const target = energy * center * travel * jitter;
        bars[index] += (target - bars[index]) * 0.35;
        const barHeight = 3 + bars[index] * (base - 8);
        const x = index * (barWidth + gap);
        const gradient = context.createLinearGradient(0, base, 0, base - barHeight);
        gradient.addColorStop(0, rgba(0.95));
        gradient.addColorStop(1, rgba(0.25));
        context.fillStyle = gradient;
        context.beginPath();
        context.roundRect(x, base - barHeight, barWidth, barHeight, Math.min(3, barWidth / 2));
        context.fill();
      }
    };

    const drawRipples = (width: number, base: number, time: number) => {
      const interval = live.phase === 'thinking' ? 0.9 : 0.22 + (1 - energy) * 0.5;
      if (visible > 0.05 && time - lastRipple > interval && (energy > 0.08 || live.phase === 'thinking')) {
        ripples.push({ born: time, strength: Math.max(0.3, energy) });
        lastRipple = time;
      }
      const life = 1.8;
      while (ripples.length && time - ripples[0].born > life) ripples.shift();
      context.lineWidth = 2;
      for (const ripple of ripples) {
        const age = (time - ripple.born) / life;
        const radius = 20 + age * Math.max(width * 0.45, base * 3) * ripple.strength;
        context.strokeStyle = rgba((1 - age) * 0.8 * ripple.strength);
        context.beginPath();
        context.ellipse(width / 2, base, radius, radius * 0.32, 0, Math.PI, Math.PI * 2);
        context.stroke();
      }
      const glow = context.createRadialGradient(width / 2, base, 0, width / 2, base, 60 + energy * 80);
      glow.addColorStop(0, rgba(0.7));
      glow.addColorStop(1, rgba(0));
      context.fillStyle = glow;
      context.fillRect(0, 0, width, base);
    };

    const drawWave = (width: number, base: number, time: number) => {
      const layers = [
        { speed: 2.2, frequency: 2.5, alpha: 0.9, scale: 1 },
        { speed: -1.6, frequency: 3.7, alpha: 0.45, scale: 0.7 },
        { speed: 3.1, frequency: 1.6, alpha: 0.3, scale: 0.5 },
      ];
      const middle = base * 0.6;
      for (const layer of layers) {
        context.beginPath();
        for (let x = 0; x <= width; x += 4) {
          const progress = x / width;
          const envelope = Math.sin(progress * Math.PI) ** 2;
          const y = middle + Math.sin(progress * Math.PI * 2 * layer.frequency + time * layer.speed) * envelope * (2 + energy * middle * 0.9) * layer.scale;
          if (x === 0) context.moveTo(x, y);
          else context.lineTo(x, y);
        }
        context.strokeStyle = rgba(layer.alpha);
        context.lineWidth = 2.5;
        context.shadowColor = rgba(0.8);
        context.shadowBlur = 12;
        context.stroke();
      }
      context.shadowBlur = 0;
    };

    const drawAurora = (width: number, base: number, time: number) => {
      const reach = 10 + energy * base * 0.95;
      for (let index = 0; index < 4; index++) {
        const center = width * (0.5 + 0.35 * Math.sin(time * (0.4 + index * 0.17) + index * 2));
        const spread = width * (0.25 + 0.1 * Math.sin(time * 0.7 + index));
        const gradient = context.createRadialGradient(center, base, 0, center, base, spread);
        const shift = index * 18;
        gradient.addColorStop(0, `rgba(${Math.min(255, color[0] + shift)},${color[1]},${Math.max(0, color[2] - shift)},${0.55 * visible})`);
        gradient.addColorStop(1, 'rgba(0,0,0,0)');
        context.save();
        context.translate(0, base);
        context.scale(1, reach / spread);
        context.translate(0, -base);
        context.fillStyle = gradient;
        context.fillRect(0, base - spread, width, spread);
        context.restore();
      }
      context.fillStyle = rgba(0.9);
      context.fillRect(0, base - 2, width, 2);
    };

    const drawOrb = (width: number, base: number, time: number) => {
      const center = width / 2;
      const middle = base * 0.55;
      const radius = 14 + energy * Math.min(base * 0.38, 46);
      const halo = context.createRadialGradient(center, middle, radius * 0.4, center, middle, radius * 2.6);
      halo.addColorStop(0, rgba(0.55));
      halo.addColorStop(1, rgba(0));
      context.fillStyle = halo;
      context.fillRect(center - radius * 3, middle - radius * 3, radius * 6, radius * 6);
      context.beginPath();
      const points = 48;
      for (let index = 0; index <= points; index++) {
        const angle = (index / points) * Math.PI * 2;
        const wobble = 1 + (0.06 + energy * 0.12) * Math.sin(angle * 3 + time * 3) * Math.sin(angle * 5 - time * 2);
        const x = center + Math.cos(angle) * radius * wobble;
        const y = middle + Math.sin(angle) * radius * wobble;
        if (index === 0) context.moveTo(x, y);
        else context.lineTo(x, y);
      }
      const body = context.createRadialGradient(center - radius * 0.3, middle - radius * 0.3, 1, center, middle, radius);
      body.addColorStop(0, `rgba(255,255,255,${0.9 * visible})`);
      body.addColorStop(0.35, rgba(0.95));
      body.addColorStop(1, rgba(0.6));
      context.fillStyle = body;
      context.fill();
    };

    const draw = (now: number) => {
      const time = now / 1000;
      const width = element.clientWidth;
      const base = element.clientHeight;
      visible += ((live.phase === 'idle' ? 0 : 1) - visible) * 0.12;
      energy += (targetEnergy(time) - energy) * (live.phase === 'listening' ? 0.45 : 0.12);
      const target = colorFor(live.phase, live.mode);
      color = color.map((channel, index) => channel + (target[index] - channel) * 0.1) as [number, number, number];
      context.clearRect(0, 0, width, base);
      if (visible > 0.01) {
        if (live.style === 'soundbars') drawSoundbars(width, base, time);
        else if (live.style === 'ripples') drawRipples(width, base, time);
        else if (live.style === 'wave') drawWave(width, base, time);
        else if (live.style === 'aurora') drawAurora(width, base, time);
        else if (live.style === 'orb') drawOrb(width, base, time);
      }
      frame = requestAnimationFrame(draw);
    };
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  });
</script>

<canvas bind:this={canvas} data-indicator-style={style} class="block w-full" style="height:{height}px"></canvas>
