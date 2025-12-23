import * as server from '../entries/pages/_layout.server.ts.js';

export const index = 0;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_layout.svelte.js')).default;
export { server };
export const server_id = "src/routes/+layout.server.ts";
export const imports = ["_app/immutable/nodes/0.DfPzoWZ7.js","_app/immutable/chunks/CE6r7iiU.js","_app/immutable/chunks/CG4jYDpo.js","_app/immutable/chunks/CRFQ9GUe.js","_app/immutable/chunks/e6oh68IZ.js"];
export const stylesheets = ["_app/immutable/assets/0.B9jyAc4k.css"];
export const fonts = [];
