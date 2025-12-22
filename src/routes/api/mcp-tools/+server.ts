import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { experimental_createMCPClient as createMCPClient } from '@ai-sdk/mcp';
import { Experimental_StdioMCPTransport } from '@ai-sdk/mcp/mcp-stdio';

type MCPServer = {
  name: string;
  transport: 'stdio' | 'http' | 'sse';
  command?: string;
  args?: string[];
  url?: string;
};

export const POST: RequestHandler = async ({ request }) => {
  let client: any = null;

  try {
    const { server } = await request.json<{
      server: MCPServer;
    }>();

    if (!server) {
      return json({ error: 'Missing server configuration' }, { status: 400 });
    }

    // Create transport based on server type
    let transport;
    if (server.transport === 'stdio') {
      if (!server.command) {
        return json({ error: 'Missing command for stdio transport' }, { status: 400 });
      }
      transport = new Experimental_StdioMCPTransport({
        command: server.command,
        args: server.args || [],
      });
    } else if (server.transport === 'sse') {
      if (!server.url) {
        return json({ error: 'Missing URL for sse transport' }, { status: 400 });
      }
      transport = {
        type: 'sse' as const,
        url: server.url,
      };
    } else if (server.transport === 'http') {
      if (!server.url) {
        return json({ error: 'Missing URL for http transport' }, { status: 400 });
      }
      transport = {
        type: 'http' as const,
        url: server.url,
      };
    } else {
      return json({ error: `Unknown transport: ${server.transport}` }, { status: 400 });
    }

    // Create MCP client
    client = await createMCPClient({
      transport,
    });

    // Get tools, prompts, and resources from this server
    const tools = await client.tools();
    let promptsCount = 0;
    let resourcesCount = 0;

    try {
      const prompts = await client.listPrompts?.() || {};
      promptsCount = Array.isArray(prompts) ? prompts.length : Object.keys(prompts).length;
    } catch (e) {
      // Prompts not available
    }

    try {
      const resources = await client.listResources?.() || {};
      resourcesCount = Array.isArray(resources) ? resources.length : Object.keys(resources).length;
    } catch (e) {
      // Resources not available
    }

    // Convert to array format
    const toolsArray = Object.entries(tools).map(([name, def]: [string, any]) => ({
      name,
      description: def.description || '',
      inputSchema: def.inputSchema || {},
    }));

    await client.close();

    return json({
      success: true,
      tools: toolsArray,
      count: toolsArray.length,
      promptsCount,
      resourcesCount,
    });
  } catch (error) {
    if (client) {
      try {
        await client.close();
      } catch (e) {
        // Ignore cleanup errors
      }
    }
    console.error('MCP Tools API error:', error);
    return json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to connect to MCP server',
        tools: [],
        count: 0,
      },
      { status: 500 }
    );
  }
};
