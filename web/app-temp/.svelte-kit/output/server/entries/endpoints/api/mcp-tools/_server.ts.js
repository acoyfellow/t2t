import { json } from "@sveltejs/kit";
import { experimental_createMCPClient } from "@ai-sdk/mcp";
import { Experimental_StdioMCPTransport } from "@ai-sdk/mcp/mcp-stdio";
const POST = async ({ request }) => {
  let client = null;
  try {
    const { server } = await request.json();
    if (!server) {
      return json({ error: "Missing server configuration" }, { status: 400 });
    }
    let transport;
    if (server.transport === "stdio") {
      if (!server.command) {
        return json({ error: "Missing command for stdio transport" }, { status: 400 });
      }
      transport = new Experimental_StdioMCPTransport({
        command: server.command,
        args: server.args || []
      });
    } else if (server.transport === "sse") {
      if (!server.url) {
        return json({ error: "Missing URL for sse transport" }, { status: 400 });
      }
      transport = {
        type: "sse",
        url: server.url
      };
    } else if (server.transport === "http") {
      if (!server.url) {
        return json({ error: "Missing URL for http transport" }, { status: 400 });
      }
      transport = {
        type: "http",
        url: server.url
      };
    } else {
      return json({ error: `Unknown transport: ${server.transport}` }, { status: 400 });
    }
    client = await experimental_createMCPClient({
      transport
    });
    const tools = await client.tools();
    const toolsArray = Object.entries(tools).map(([name, def]) => ({
      name,
      description: def.description || "",
      inputSchema: def.inputSchema || {}
    }));
    await client.close();
    return json({
      success: true,
      tools: toolsArray,
      count: toolsArray.length
    });
  } catch (error) {
    if (client) {
      try {
        await client.close();
      } catch (e) {
      }
    }
    console.error("MCP Tools API error:", error);
    return json(
      {
        success: false,
        error: error instanceof Error ? error.message : "Failed to connect to MCP server",
        tools: [],
        count: 0
      },
      { status: 500 }
    );
  }
};
export {
  POST
};
