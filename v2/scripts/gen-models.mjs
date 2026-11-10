import { readFileSync, writeFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('../node_modules/@earendil-works/pi-ai/dist/providers/data/opencode.json', import.meta.url), 'utf8'));
const models = [];
for (const [api, entries] of Object.entries(data)) {
  for (const model of Object.values(entries)) {
    if (!model.id || model.classifier) continue;
    const family = model.id.includes('claude') ? 'Anthropic' : model.id.includes('gpt') || model.id.includes('o3') || model.id.includes('o4') ? 'OpenAI' : model.id.includes('muse') ? 'Muse' : model.id.includes('gemini') || model.id.includes('gemma') ? 'Google' : model.id.includes('deepseek') ? 'DeepSeek' : model.id.includes('qwen') ? 'Qwen' : model.id.includes('kimi') ? 'Moonshot' : model.id.includes('glm') ? 'Zhipu' : model.id.includes('llama') ? 'Meta' : model.id.includes('mistral') ? 'Mistral' : model.id.includes('minimax') ? 'MiniMax' : model.id.includes('nemotron') ? 'NVIDIA' : 'Other';
    models.push({ id: model.id, name: model.name ?? model.id, family, api, cost: model.cost ?? null });
  }
}
models.sort((a, b) => a.family.localeCompare(b.family) || a.name.localeCompare(b.name));
writeFileSync(new URL('../ui/src/lib/models.json', import.meta.url), JSON.stringify(models, null, 2) + '\n');
console.log(`wrote ${models.length} models`);
