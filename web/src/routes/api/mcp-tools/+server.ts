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

    // Get tools from this server
    const tools = await client.tools();

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
    
    // Provide more descriptive error messages
    let errorMessage = 'Failed to connect to MCP server';
    if (error instanceof Error) {
      const msg = error.message.toLowerCase();
      if (msg.includes('enoent') || msg.includes('not found')) {
        errorMessage = `Command not found: ${server.command || 'unknown'}. Make sure the MCP server package is installed.`;
      } else if (msg.includes('timeout') || msg.includes('timed out')) {
        errorMessage = `Connection timeout: The MCP server took too long to respond. Check if the server is running.`;
      } else if (msg.includes('econnrefused') || msg.includes('connection refused')) {
        errorMessage = `Connection refused: Unable to connect to ${server.url || 'server'}. Check if the URL is correct and the server is running.`;
      } else if (msg.includes('fetch') || msg.includes('network')) {
        errorMessage = `Network error: Unable to reach ${server.url || 'server'}. Check your internet connection and server URL.`;
      } else if (msg.includes('spawn') || msg.includes('exec')) {
        errorMessage = `Failed to start process: ${error.message}`;
      } else {
        errorMessage = `Connection error: ${error.message}`;
      }
    }
    
    return json(
      {
        success: false,
        error: errorMessage,
        tools: [],
        count: 0,
      },
      { status: 500 }
    );
  }
};
