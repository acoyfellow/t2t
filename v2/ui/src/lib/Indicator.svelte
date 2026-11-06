<script lang="ts" module>
  export const indicatorStyles = [
    { id: 'classic', label: 'Classic bar' },
    { id: 'soundbars', label: 'Sound bars' },
    { id: 'wave', label: 'Waveform' },
    { id: 'aurora', label: 'Aurora' },
    { id: 'orb', label: 'Orb' },
  ] as const;
  export type IndicatorStyle = (typeof indicatorStyles)[number]['id'];
  export const isIndicatorStyle = (value: unknown): value is IndicatorStyle => indicatorStyles.some((option) => option.id === value);
  export type IndicatorPhase = 'idle' | 'listening' | 'thinking' | 'speaking';
</script>

<script lang="ts">
  import { auroraShader, orbShader, vertexShader } from './shaders';

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

  const shaderFor: Partial<Record<IndicatorStyle, string>> = { aurora: auroraShader, orb: orbShader };

  function targetEnergy(current: IndicatorPhase, currentLevel: number, time: number) {
    if (current === 'listening') return Math.min(1, currentLevel * 1.4);
    if (current === 'speaking') return 0.3 + 0.45 * Math.abs(Math.sin(time * 7.3)) * (0.6 + 0.4 * Math.sin(time * 2.1));
    if (current === 'thinking') return 0.18 + 0.08 * Math.sin(time * 3);
    return 0;
  }

  const compile = (gl: WebGLRenderingContext, type: number, source: string) => {
    const shader = gl.createShader(type);
    if (!shader) throw new Error('createShader failed');
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader) ?? 'shader compile failed');
    return shader;
  };

  const runShader = (element: HTMLCanvasElement, source: string) => {
    const visibleContext = element.getContext('2d');
    if (!visibleContext) throw new Error('no 2d context');
    const offscreen = document.createElement('canvas');
    const gl = offscreen.getContext('webgl', { premultipliedAlpha: true, alpha: true, antialias: false, preserveDrawingBuffer: true });
    if (!gl) throw new Error('no webgl context');
    const program = gl.createProgram();
    if (!program) return () => {};
    gl.attachShader(program, compile(gl, gl.VERTEX_SHADER, vertexShader));
    gl.attachShader(program, compile(gl, gl.FRAGMENT_SHADER, source));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program) ?? 'link failed');
    gl.useProgram(program);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const position = gl.getAttribLocation(program, 'a_position');
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
    const resolution = gl.getUniformLocation(program, 'u_res');
    const timeUniform = gl.getUniformLocation(program, 'u_time');
    const energyUniform = gl.getUniformLocation(program, 'u_energy');
    const visibleUniform = gl.getUniformLocation(program, 'u_visible');
    const colorUniform = gl.getUniformLocation(program, 'u_color');
    gl.clearColor(0, 0, 0, 0);

    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      element.width = Math.round(element.clientWidth * ratio);
      element.height = Math.round(element.clientHeight * ratio);
      offscreen.width = element.width;
      offscreen.height = element.height;
      gl.viewport(0, 0, offscreen.width, offscreen.height);
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);

    let frame = 0;
    let visible = 0;
    let energy = 0;
    let color: [number, number, number] = colorFor(live.phase, live.mode);
    const start = performance.now();
    const draw = (now: number) => {
      const time = (now - start) / 1000;
      visible += ((live.phase === 'idle' ? 0 : 1) - visible) * 0.08;
      energy += (targetEnergy(live.phase, live.level, time) - energy) * (live.phase === 'listening' ? 0.3 : 0.08);
      const target = colorFor(live.phase, live.mode);
      color = color.map((channel, index) => channel + (target[index] - channel) * 0.06) as [number, number, number];
      gl.clear(gl.COLOR_BUFFER_BIT);
      if (visible > 0.005) {
        gl.uniform2f(resolution, element.width, element.height);
        gl.uniform1f(timeUniform, time);
        gl.uniform1f(energyUniform, energy);
        gl.uniform1f(visibleUniform, visible);
        gl.uniform3f(colorUniform, color[0] / 255, color[1] / 255, color[2] / 255);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      }
      visibleContext.clearRect(0, 0, element.width, element.height);
      if (visible > 0.005) visibleContext.drawImage(offscreen, 0, 0);
      frame = requestAnimationFrame(draw);
    };
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    };
  };

  $effect(() => {
    if (!canvas) return;
    const shader = shaderFor[style];
    if (shader) {
      try {
        return runShader(canvas, shader);
      } catch (error) {
        window.webkit?.messageHandlers?.t2t?.postMessage({ command: 'log', line: `indicator ${style} failed: ${error}` });
        return;
      }
    }
    const context = canvas.getContext('2d');
    if (!context) return;
    const element = canvas;
    let frame = 0;
    let visible = 0;
    let energy = 0;
    let color: [number, number, number] = [194, 122, 255];
    const bars = Array.from({ length: 72 }, () => 0);

    const resize = () => {
      const ratio = window.devicePixelRatio || 1;
      element.width = Math.round(element.clientWidth * ratio);
      element.height = Math.round(element.clientHeight * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(element);


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

    const draw = (now: number) => {
      const time = now / 1000;
      const width = element.clientWidth;
      const base = element.clientHeight;
      visible += ((live.phase === 'idle' ? 0 : 1) - visible) * 0.12;
      energy += (targetEnergy(live.phase, live.level, time) - energy) * (live.phase === 'listening' ? 0.45 : 0.12);
      const target = colorFor(live.phase, live.mode);
      color = color.map((channel, index) => channel + (target[index] - channel) * 0.1) as [number, number, number];
      context.clearRect(0, 0, width, base);
      if (visible > 0.01) {
        if (live.style === 'soundbars') drawSoundbars(width, base, time);
        else if (live.style === 'wave') drawWave(width, base, time);
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
