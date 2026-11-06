export const vertexShader = `
attribute vec2 a_position;
void main() { gl_Position = vec4(a_position, 0.0, 1.0); }
`;

const common = `
precision highp float;
uniform vec2 u_res;
uniform float u_time;
uniform float u_energy;
uniform float u_visible;
uniform vec3 u_color;

float hash2(vec2 p) {
  p = fract(p * vec2(123.34, 456.21));
  p += dot(p, p + 45.32);
  return fract(p.x * p.y);
}

float noise2(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash2(i), hash2(i + vec2(1.0, 0.0)), u.x), mix(hash2(i + vec2(0.0, 1.0)), hash2(i + vec2(1.0, 1.0)), u.x), u.y);
}

float fbm2(vec2 p) {
  float value = 0.0;
  float amplitude = 0.5;
  mat2 rotate = mat2(1.6, 1.2, -1.2, 1.6);
  for (int i = 0; i < 5; i++) {
    value += amplitude * noise2(p);
    p = rotate * p;
    amplitude *= 0.5;
  }
  return value;
}

vec3 hueShift(vec3 color, float angle) {
  const vec3 axis = vec3(0.57735);
  float c = cos(angle);
  return color * c + cross(axis, color) * sin(angle) + axis * dot(axis, color) * (1.0 - c);
}

vec3 tonemap(vec3 color) { return 1.0 - exp(-color); }
`;

export const auroraShader = `${common}
vec3 curtain(vec2 uv, float aspect, float t, float seed, float reach) {
  float x = uv.x * aspect;
  float fold = fbm2(vec2(x * 0.55 + seed, t * 0.06 + seed)) - 0.5;
  float ripple = fbm2(vec2(x * 2.2 - t * 0.25, seed * 3.0)) - 0.5;
  float edge = 0.05 + reach * 0.1 + fold * (0.1 + reach * 0.35) + ripple * 0.06 * (0.4 + reach);
  float above = uv.y - edge;
  float span = 0.08 + reach * 0.75;

  float rayCoordinate = x * 9.0 + fold * 14.0 + ripple * 6.0;
  float rays = noise2(vec2(rayCoordinate, t * 0.5 + seed)) * 0.65 + noise2(vec2(rayCoordinate * 3.1, -t * 0.4 + seed)) * 0.35;
  rays = smoothstep(0.25, 0.95, rays);

  float lowerLine = exp(-abs(above) * (90.0 - reach * 40.0)) * step(-0.02, above);
  float body = step(0.0, above) * exp(-above / span * 2.2) * (0.35 + 1.4 * rays);
  float below = step(above, 0.0) * exp(above * 60.0) * 0.35;
  float brightness = (lowerLine * 1.6 + body + below) * (0.55 + 0.9 * (fold + 0.5));

  float heightMix = clamp(above / span, 0.0, 1.0);
  vec3 base = u_color;
  vec3 top = hueShift(u_color, 1.3);
  vec3 edgeColor = mix(u_color, vec3(1.0), 0.35);
  vec3 color = mix(edgeColor, mix(base, top, smoothstep(0.15, 0.9, heightMix)), smoothstep(0.0, 0.04, above));
  return color * brightness;
}

void main() {
  vec2 uv = gl_FragCoord.xy / u_res;
  float aspect = u_res.x / u_res.y;
  float t = u_time;
  float reach = u_energy;
  vec3 light = curtain(uv, aspect, t, 1.3, reach) * 0.9;
  light += curtain(uv + vec2(0.0, 0.03), aspect, t * 0.8, 7.9, reach * 0.75) * 0.45;
  light += curtain(uv + vec2(0.0, -0.01), aspect, t * 1.2, 15.1, reach * 0.5) * 0.3;
  float stars = step(0.997, hash2(floor(gl_FragCoord.xy / 2.0))) * 0.25 * smoothstep(0.3, 1.0, uv.y);
  light *= smoothstep(1.0, 0.55, uv.y);
  vec3 color = tonemap(light * 1.4);
  color += (hash2(gl_FragCoord.xy + fract(t)) - 0.5) / 255.0;
  float alpha = clamp(max(color.r, max(color.g, color.b)) + stars * 0.0, 0.0, 1.0) * u_visible;
  gl_FragColor = vec4(color * u_visible, alpha);
}
`;

export const orbShader = `${common}
float hash1(float n) { return fract(sin(n) * 43758.5453); }

float noise3(vec3 p) {
  vec3 i = floor(p);
  vec3 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  float n = dot(i, vec3(1.0, 57.0, 113.0));
  return mix(
    mix(mix(hash1(n), hash1(n + 1.0), f.x), mix(hash1(n + 57.0), hash1(n + 58.0), f.x), f.y),
    mix(mix(hash1(n + 113.0), hash1(n + 114.0), f.x), mix(hash1(n + 170.0), hash1(n + 171.0), f.x), f.y),
    f.z
  );
}

float fbm3(vec3 p) {
  float value = 0.0;
  float amplitude = 0.5;
  for (int i = 0; i < 4; i++) {
    value += amplitude * noise3(p);
    p = p * 2.03 + vec3(1.7, 9.2, 3.1);
    amplitude *= 0.5;
  }
  return value;
}

float radius() { return 0.27 + u_energy * 0.11; }

float field(vec3 p) {
  float warp = fbm3(p * 1.3 + vec3(0.0, u_time * 0.3, u_time * 0.45));
  float swell = noise3(p * 2.2 + warp * 1.2 - vec3(u_time * 0.5));
  float amount = (0.05 + u_energy * 0.22) * radius();
  return length(p) - radius() - (swell - 0.5) * amount * 2.0;
}

vec3 normalAt(vec3 p) {
  vec2 e = vec2(0.0015, 0.0);
  return normalize(vec3(
    field(p + e.xyy) - field(p - e.xyy),
    field(p + e.yxy) - field(p - e.yxy),
    field(p + e.yyx) - field(p - e.yyx)
  ));
}

void main() {
  vec2 uv = (gl_FragCoord.xy - vec2(0.5 * u_res.x, 0.52 * u_res.y)) / u_res.y;
  float limit = radius() * 1.7;
  if (length(uv) > limit) {
    gl_FragColor = vec4(0.0);
    return;
  }

  vec3 origin = vec3(0.0, 0.0, 2.4);
  vec3 direction = normalize(vec3(uv, -2.4));
  float travelled = 0.0;
  float closest = 1e3;
  bool hit = false;
  vec3 position = origin;
  for (int i = 0; i < 72; i++) {
    position = origin + direction * travelled;
    float distance = field(position);
    closest = min(closest, distance);
    if (distance < 0.0008) { hit = true; break; }
    travelled += distance * 0.7;
    if (travelled > 4.0) break;
  }

  float pixel = 1.5 / u_res.y;
  float coverage = hit ? 1.0 : 1.0 - smoothstep(0.0, pixel, closest);
  if (coverage <= 0.0) {
    gl_FragColor = vec4(0.0);
    return;
  }

  vec3 normal = normalAt(position);
  vec3 view = -direction;
  vec3 light = normalize(vec3(-0.5, 0.8, 0.55));
  float facing = max(dot(normal, view), 0.0);
  float fresnel = pow(1.0 - facing, 3.0);

  vec3 inward = normalize(direction - normal * 0.25);
  vec3 glow = vec3(0.0);
  float stepLength = radius() * 2.0 / 28.0;
  vec3 sample = position + inward * stepLength * 0.5;
  for (int i = 0; i < 28; i++) {
    float shell = min(length(sample) / (radius() * 1.25), 1.0);
    vec3 flow = sample * 4.5 + vec3(0.0, -u_time * 0.6, u_time * 0.35);
    float n = fbm3(flow + fbm3(flow * 0.7 + u_time * 0.2) * 1.5);
    float filament = pow(1.0 - abs(n - 0.5) * 2.0, 16.0 - u_energy * 6.0);
    float density = filament * (1.0 - shell * shell) * (0.6 + u_energy * 1.4);
    vec3 tint = mix(u_color, hueShift(u_color, 0.9), shell);
    glow += tint * density * stepLength * 6.0;
    sample += inward * stepLength;
  }

  float thickness = 1.0 - facing + u_time * 0.03;
  vec3 film = 0.5 + 0.5 * cos(6.28318 * (vec3(0.0, 0.33, 0.67) + thickness * 2.2));
  vec3 rim = mix(u_color * 1.2, film, 0.6) * fresnel * 1.4;

  vec3 color = u_color * 0.04 + glow + rim;
  vec3 halfway = normalize(light + view);
  color += vec3(1.0) * pow(max(dot(normal, halfway), 0.0), 120.0) * 1.4;
  color += vec3(1.0) * smoothstep(0.92, 1.0, pow(max(dot(normal, normalize(vec3(0.45, -0.55, 0.7))), 0.0), 2.0)) * 0.12;
  color = tonemap(color * 1.3);

  float alpha = coverage * u_visible;
  gl_FragColor = vec4(color * alpha, alpha);
}
`;
