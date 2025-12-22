import alchemy from "alchemy";
import { Worker, Ai } from "alchemy/cloudflare";

const app = await alchemy("t2t-agent", {
  stage: process.env.ALCHEMY_STAGE ?? "dev",
});

export const worker = await Worker("agent-api", {
  entrypoint: "./src/index.ts",
  url: true,
  compatibilityDate: "2024-12-01",
  compatibilityFlags: ["nodejs_compat"],
  bindings: {
    AI: Ai(),
  },
  dev: {
    port: 1337,
  }
});

console.log(`Worker URL: ${worker.url}`);

await app.finalize();
