export interface McpServer {
  id: string
  name: string
  status: "active" | "loading" | "error"
  statusMessage?: string
  enabled: boolean
  toolsCount?: number
  promptsCount?: number
  resourcesCount?: number
  expandable?: boolean
  expanded?: boolean
  expandedContent?: string[]
  actions?: string[]
}
