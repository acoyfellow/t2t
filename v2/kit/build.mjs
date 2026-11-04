import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const kit = readFileSync(join(import.meta.dirname, 'scene.js'), 'utf8').replace(/^export /gm, '');

export const sceneDocument = (scene) => `<!doctype html><html><head><meta charset="utf-8"><title>${scene.title}</title><style id="kit-css"></style></head><body><script>
${kit}
document.getElementById('kit-css').textContent = css;
play(${JSON.stringify(scene)});
</script></body></html>`;

if (process.argv[2] && process.argv[2] !== "--worker") {
  const scene = JSON.parse(readFileSync(process.argv[2], 'utf8'));
  writeFileSync(process.argv[3] ?? '/dev/stdout', sceneDocument(scene));
}

export const writeWorkerModule = () => {
  const target = join(import.meta.dirname, '..', 'worker', 'src', 'kit.generated.ts');
  writeFileSync(target, `export const KIT_SOURCE = ${JSON.stringify(kit)};\n`);
  return target;
};

if (process.argv[2] === '--worker') console.log(writeWorkerModule());
