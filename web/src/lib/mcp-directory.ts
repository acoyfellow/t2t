export type MCPCategory = 'database' | 'filesystem' | 'api' | 'code' | 'other';
export type Transport = 'stdio' | 'http' | 'sse';

export interface MCPEntry {
  id: string;
  name: string;
  description: string;
  category: MCPCategory;
  transport: Transport;
  config: {
    name: string;
    transport: Transport;
    command?: string;
    args?: string[];
    url?: string;
    enabled?: boolean;
  };
  verified?: boolean;
}

export const mcpDirectory: MCPEntry[] = [
  {
    id: 'svelte',
    name: 'Svelte MCP',
    description: 'Official Svelte 5 and SvelteKit documentation, code examples, and autofixer tools.',
    category: 'code',
    transport: 'stdio',
    config: {
      name: 'Svelte MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@sveltejs/mcp'],
      enabled: true,
    },
    verified: true,
  },
  /*
  "stagehand-docs": {
      "url": "https://docs.stagehand.dev/mcp"
    },
  */
  {
    id: 'effect-solutions',
    name: 'Effect Solutions MCP',
    description: 'Effect Solutions MCP',
    category: 'code',
    transport: 'stdio',
    config: {
      name: 'Effect Solutions MCP',
      transport: 'stdio',
      command: 'bunx',
      args: ['effect-solutions-mcp@latest'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'stagehand-docs',
    name: 'Stagehand Docs MCP',
    description: 'Official Stagehand documentation, code examples, and autofixer tools.',
    category: 'code',
    transport: 'http',
    config: {
      name: 'Stagehand Docs MCP',
      transport: 'http',
      url: 'https://docs.stagehand.dev/mcp',
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'filesystem',
    name: 'Filesystem MCP',
    description: 'Read, write, and manage files and directories on your local system.',
    category: 'filesystem',
    transport: 'stdio',
    config: {
      name: 'Filesystem MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'postgres',
    name: 'Postgres MCP',
    description: 'Query and manage PostgreSQL databases with SQL tools.',
    category: 'database',
    transport: 'stdio',
    config: {
      name: 'Postgres MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-postgres'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'github',
    name: 'GitHub MCP',
    description: 'Interact with GitHub repositories, issues, pull requests, and more.',
    category: 'api',
    transport: 'http',
    config: {
      name: 'GitHub MCP',
      transport: 'http',
      url: 'https://api.github.com/mcp',
      enabled: true,
    },
    verified: false,
  },
  {
    id: 'git',
    name: 'Git MCP',
    description: 'Execute git commands and manage repositories programmatically.',
    category: 'code',
    transport: 'stdio',
    config: {
      name: 'Git MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-git'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'puppeteer',
    name: 'Puppeteer MCP',
    description: 'Control headless browsers for web scraping and automation.',
    category: 'api',
    transport: 'stdio',
    config: {
      name: 'Puppeteer MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-puppeteer'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'convex',
    name: 'Convex MCP',
    description: 'Interact with your Convex deployment: query deployments, list tables, access data, and execute functions.',
    category: 'database',
    transport: 'stdio',
    config: {
      name: 'Convex MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'convex@latest', 'mcp', 'start'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'chrome-devtools',
    name: 'Chrome DevTools MCP',
    description: 'Control and inspect a live Chrome browser for automation, debugging, and performance analysis.',
    category: 'api',
    transport: 'stdio',
    config: {
      name: 'Chrome DevTools MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'chrome-devtools-mcp@latest'],
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'context7',
    name: 'Context7 MCP',
    description: 'Up-to-date, version-specific documentation and code examples for various libraries and frameworks.',
    category: 'code',
    transport: 'http',
    config: {
      name: 'Context7 MCP',
      transport: 'http',
      url: 'https://mcp.context7.com/mcp',
      enabled: true,
    },
    verified: true,
  },
  {
    id: 'google',
    name: 'Google MCP',
    description: 'Access Google Cloud services including Maps, BigQuery, Kubernetes Engine, and Compute Engine.',
    category: 'api',
    transport: 'stdio',
    config: {
      name: 'Google MCP',
      transport: 'stdio',
      command: 'npx',
      args: ['-y', 'google-mcp@latest'],
      enabled: true,
    },
    verified: true,
  },
];

export const categories: MCPCategory[] = ['database', 'filesystem', 'api', 'code', 'other'];

export function getCategoryLabel(category: MCPCategory): string {
  const labels: Record<MCPCategory, string> = {
    database: 'Database',
    filesystem: 'Filesystem',
    api: 'API',
    code: 'Code',
    other: 'Other',
  };
  return labels[category];
}

export function getCategoryColor(category: MCPCategory): string {
  const colors: Record<MCPCategory, string> = {
    database: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    filesystem: 'bg-green-500/20 text-green-400 border-green-500/30',
    api: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    code: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
    other: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };
  return colors[category];
}

