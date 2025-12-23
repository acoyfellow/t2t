var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker/index.ts
import { DurableObject } from "cloudflare:workers";
var MyDO = class extends DurableObject {
  static {
    __name(this, "MyDO");
  }
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const key = url.pathname.slice(1);
      if (request.method === "GET") {
        const value = await this.ctx.storage.get(key);
        return Response.json({
          key,
          value: value || null,
          id: this.ctx.id.toString()
        });
      }
      if (request.method === "POST") {
        const body = await request.json();
        await this.ctx.storage.put(key, body.value);
        return Response.json({
          key,
          value: body.value,
          id: this.ctx.id.toString()
        });
      }
      if (request.method === "DELETE") {
        await this.ctx.storage.delete(key);
        return Response.json({
          key,
          deleted: true,
          id: this.ctx.id.toString()
        });
      }
      return new Response("Method not allowed", { status: 405 });
    } catch (error) {
      console.error("Durable Object error:", error);
      return new Response(
        JSON.stringify({ error: "Storage temporarily unavailable" }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }
};
var index_default = {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;
      if (pathname.startsWith("/api/storage/")) {
        const key = pathname.replace("/api/storage/", "");
        if (!key || key.length > 50) {
          return new Response("Invalid key", { status: 400 });
        }
        const id = env.MY_DO.idFromName(key);
        const doInstance = env.MY_DO.get(id);
        return await doInstance.fetch(request);
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error("Worker error:", error);
      return new Response(
        JSON.stringify({ error: "Service temporarily unavailable" }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }
};
export {
  MyDO,
  index_default as default
};
//# sourceMappingURL=index.js.map
