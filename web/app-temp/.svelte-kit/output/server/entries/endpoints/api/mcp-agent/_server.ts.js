import { json } from "@sveltejs/kit";
import { generateText } from "ai";
import { experimental_createMCPClient } from "@ai-sdk/mcp";
import { Experimental_StdioMCPTransport } from "@ai-sdk/mcp/mcp-stdio";
import { createOpenRouter } from "@openrouter/ai-sdk-provider";
const POST = async ({ request }) => {
  const clients = [];
  try {
    const { transcript, mcpServers, openrouterKey } = await request.json();
    if (!transcript || typeof transcript !== "string") {
      return json({ error: "Missing transcript" }, { status: 400 });
    }
    if (!mcpServers || !Array.isArray(mcpServers) || mcpServers.length === 0) {
      return json({ error: "No MCP servers configured" }, { status: 400 });
    }
    if (!openrouterKey || typeof openrouterKey !== "string") {
      return json({ error: "Missing OpenRouter API key" }, { status: 400 });
    }
    const allTools = {};
    for (const server of mcpServers) {
      try {
        let transport;
        if (server.transport === "stdio") {
          if (!server.command) {
            console.warn(`Skipping server ${server.name}: missing command`);
            continue;
          }
          transport = new Experimental_StdioMCPTransport({
            command: server.command,
            args: server.args || []
          });
        } else if (server.transport === "sse") {
          if (!server.url) {
            console.warn(`Skipping server ${server.name}: missing URL`);
            continue;
          }
          transport = {
            type: "sse",
            url: server.url
          };
        } else if (server.transport === "http") {
          if (!server.url) {
            console.warn(`Skipping server ${server.name}: missing URL`);
            continue;
          }
          transport = {
            type: "http",
            url: server.url
          };
        } else {
          console.warn(`Unknown transport for server ${server.name}: ${server.transport}`);
          continue;
        }
        const client = await experimental_createMCPClient({
          transport
        });
        const tools = await client.tools();
        for (const [toolName, toolDef] of Object.entries(tools)) {
          const prefixedName = `${server.name}_${toolName}`;
          allTools[prefixedName] = {
            ...toolDef,
            name: prefixedName,
            description: `${toolDef.description || ""} (from ${server.name})`
          };
        }
        clients.push({ client, serverName: server.name });
      } catch (error) {
        console.error(`Failed to connect to MCP server ${server.name}:`, error);
      }
    }
    const cleanup = async () => {
      for (const { client } of clients) {
        try {
          await client.close();
        } catch (e) {
        }
      }
    };
    if (Object.keys(allTools).length === 0) {
      await cleanup();
      return json({ error: "No tools available from MCP servers" }, { status: 400 });
    }
    const openrouter = createOpenRouter({
      apiKey: openrouterKey
    });
    const result = await generateText({
      model: openrouter("openai/gpt-4o"),
      tools: allTools,
      prompt: transcript
    });
    await cleanup();
    return json({
      success: true,
      text: result.text,
      toolCalls: result.toolCalls || []
    });
  } catch (error) {
    for (const { client } of clients) {
      try {
        await client.close();
      } catch (e) {
      }
    }
    console.error("MCP Agent API error:", error);
    return json(
      { error: error instanceof Error ? error.message : "Internal server error", success: false },
      { status: 500 }
    );
  }
};
export {
  POST
};
