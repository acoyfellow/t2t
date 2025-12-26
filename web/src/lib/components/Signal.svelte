<script lang="ts">
  import { onMount, onDestroy } from "svelte";

  type SignalThreadProps = {
    color?: string;
    backgroundColor?: string;
    speed?: number;
    breathSpeed?: number;
    pulseSpeed?: number;
    amplitude?: number;
    baseAmplitude?: number;
    opacity?: number;
    pulseOpacity?: number;
    lineWidth?: number;
    trailEffect?: boolean;
    glowIntensity?: number;
    frequency?: number;
  };
  const defaultProps: SignalThreadProps = {
    color: "#ffffff",
    backgroundColor: "#000000",
    speed: 1,
    breathSpeed: 1,
    pulseSpeed: 1,
    amplitude: 15,
    baseAmplitude: 2,
    opacity: 0.6,
    pulseOpacity: 0.4,
    lineWidth: 1,
    trailEffect: true,
    glowIntensity: 1,
    frequency: 0.008,
  };
  // Props with defaults
  let {
    color = defaultProps.color,
    backgroundColor = defaultProps.backgroundColor,
    speed = defaultProps.speed,
    breathSpeed = defaultProps.breathSpeed,
    pulseSpeed = defaultProps.pulseSpeed,
    amplitude = defaultProps.amplitude,
    baseAmplitude = defaultProps.baseAmplitude,
    opacity = defaultProps.opacity,
    pulseOpacity = defaultProps.pulseOpacity,
    lineWidth = defaultProps.lineWidth,
    trailEffect = defaultProps.trailEffect,
    glowIntensity = defaultProps.glowIntensity,
    frequency = defaultProps.frequency,
  }: SignalThreadProps = $props();

  let canvas = $state<HTMLCanvasElement | null>(null);
  let animationId = $state<number | null>(null);

  onMount(() => {
    if (!canvas) return;

    const ctx = canvas.getContext("2d") as CanvasRenderingContext2D;
    let frame = 0;

    const resize = () => {
      const parent = canvas?.parentElement;
      if (parent) {
        canvas!.width = parent.clientWidth;
        canvas!.height = parent.clientHeight;
      }
    };

    resize();
    window.addEventListener("resize", resize);

    const animate = () => {
      const w = canvas!.width;
      const h = canvas!.height;

      // Trail effect or full clear
      if (trailEffect) {
        ctx.fillStyle = `${backgroundColor}10`;
        ctx.fillRect(0, 0, w, h);
      } else {
        ctx.fillStyle = backgroundColor;
        ctx.fillRect(0, 0, w, h);
      }

      const breath = Math.sin(frame * 0.008 * breathSpeed);
      const pulse = Math.pow(Math.sin(frame * 0.02 * pulseSpeed), 2);

      // Calculate dynamic amplitude
      const currentAmplitude =
        baseAmplitude + breath * amplitude + pulse * (amplitude * 1.5);

      // Glow effect
      if (glowIntensity > 0) {
        ctx.shadowBlur = 10 + pulse * 20;
        ctx.shadowColor = color;
      }

      // Draw the main line
      ctx.beginPath();
      ctx.strokeStyle = `rgba(${hexToRgb(color)}, ${opacity + pulse * pulseOpacity})`;
      ctx.lineWidth = lineWidth;

      for (let x = 0; x < w; x++) {
        const y =
          h / 2 +
          Math.sin(x * frequency + frame * 0.015 * speed) * currentAmplitude;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Additional glow layer
      if (glowIntensity > 0) {
        ctx.beginPath();
        ctx.strokeStyle = `rgba(${hexToRgb(color)}, ${(opacity + pulse * pulseOpacity) * 0.3})`;
        ctx.lineWidth = lineWidth * 3;

        for (let x = 0; x < w; x++) {
          const y =
            h / 2 +
            Math.sin(x * frequency + frame * 0.015 * speed) * currentAmplitude;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
      }

      ctx.shadowBlur = 0;

      frame++;
      animationId = requestAnimationFrame(animate) as unknown as number;
    };

    animate();

    return () => {
      window.removeEventListener("resize", resize);
      if (animationId) cancelAnimationFrame(animationId);
    };
  });

  onDestroy(() => {
    if (animationId) cancelAnimationFrame(animationId);
  });

  function hexToRgb(hex: string) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result
      ? `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}`
      : "255, 255, 255";
  }

  function isTransparent(bg: string): boolean {
    if (!bg || bg === "transparent") return true;
    if (bg.startsWith("rgba")) {
      const match = bg.match(/rgba?\([^)]+\)/);
      if (match) {
        const parts = match[0].match(/[\d.]+/g);
        if (parts && parts.length >= 4) {
          return parseFloat(parts[3]) === 0;
        }
      }
    }
    return false;
  }
</script>

<canvas
  bind:this={canvas}
  class="w-full h-full"
  style="display: block;"
  aria-hidden="true"
></canvas>
