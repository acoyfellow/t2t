import type { McpServer } from "./types"

export const mockServers: McpServer[] = [
  {
    id: "1",
    name: "svelte",
    status: "active",
    enabled: true,
    toolsCount: 4,
    promptsCount: 1,
    resourcesCount: 175,
  },
  {
    id: "2",
    name: "cloudflare",
    status: "active",
    enabled: true,
    toolsCount: 2,
    promptsCount: 1,
    statusMessage: "enabled",
  },
  {
    id: "3",
    name: "anytool",
    status: "loading",
    enabled: true,
  },
  {
    id: "4",
    name: "Effect Solutions",
    status: "active",
    enabled: true,
    toolsCount: 3,
    resourcesCount: 1,
    statusMessage: "enabled",
  },
  {
    id: "5",
    name: "stagehand-docs",
    status: "active",
    enabled: true,
    expandable: true,
    expanded: false,
    expandedContent: ["SearchStagehand"],
    actions: ["logout"],
  },
  {
    id: "6",
    name: "jordans-laptop",
    status: "loading",
    enabled: true,
  },
  {
    id: "7",
    name: "ghl-mcp",
    status: "error",
    statusMessage: "Error",
    enabled: true,
    expandable: true,
  },
]

// Mock CRUD operations
export const addServer = async (serverData: Partial<McpServer>) => {
  await new Promise((resolve) => setTimeout(resolve, 1000))
  console.log("[v0] Adding server:", serverData)
  return {
    id: String(Date.now()),
    ...serverData,
  } as McpServer
}

export const deleteServer = async (id: string) => {
  await new Promise((resolve) => setTimeout(resolve, 500))
  console.log("[v0] Deleting server:", id)
}

export const toggleServer = async (id: string) => {
  await new Promise((resolve) => setTimeout(resolve, 300))
  console.log("[v0] Toggling server:", id)
}

export const updateServer = async (id: string, data: Partial<McpServer>) => {
  await new Promise((resolve) => setTimeout(resolve, 500))
  console.log("[v0] Updating server:", id, data)
}
