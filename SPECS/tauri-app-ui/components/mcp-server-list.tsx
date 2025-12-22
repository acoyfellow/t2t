"use client"

import { useState, useEffect } from "react"
import { McpServerItem } from "./mcp-server-item"
import type { McpServer } from "@/lib/types"
import { mockServers, deleteServer, toggleServer } from "@/lib/mock-data"

export function McpServerList() {
  const [servers, setServers] = useState<McpServer[]>([])
  const [loading, setLoading] = useState(true)

  // Simulate fetching servers on mount
  useEffect(() => {
    const fetchServers = async () => {
      setLoading(true)
      // Simulate API delay
      await new Promise((resolve) => setTimeout(resolve, 800))
      setServers(mockServers)
      setLoading(false)
    }

    fetchServers()
  }, [])

  const handleToggle = async (id: string) => {
    const server = servers.find((s) => s.id === id)
    if (!server) return

    // Optimistically update UI
    setServers((prev) => prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)))

    // Simulate API call
    await toggleServer(id)
  }

  const handleDelete = async (id: string) => {
    // Optimistically update UI
    setServers((prev) => prev.filter((s) => s.id !== id))

    // Simulate API call
    await deleteServer(id)
  }

  const handleExpand = (id: string) => {
    setServers((prev) => prev.map((s) => (s.id === id ? { ...s, expanded: !s.expanded } : s)))
  }

  const handleAction = async (id: string, action: string) => {
    console.log(`[v0] Action ${action} triggered for server ${id}`)

    if (action === "logout") {
      // Simulate logout
      await new Promise((resolve) => setTimeout(resolve, 500))
      setServers((prev) => prev.map((s) => (s.id === id ? { ...s, status: "error", statusMessage: "Logged out" } : s)))
    } else if (action === "show-output") {
      console.log("[v0] Showing output for server", id)
    }
  }

  if (loading) {
    return (
      <div className="px-6 py-8 flex items-center justify-center">
        <div className="flex items-center gap-3 text-muted-foreground">
          <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span className="text-sm">Loading servers...</span>
        </div>
      </div>
    )
  }

  if (servers.length === 0) {
    return (
      <div className="px-6 py-12 text-center">
        <p className="text-muted-foreground text-sm">No servers installed yet</p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-border">
      {servers.map((server) => (
        <McpServerItem
          key={server.id}
          server={server}
          onToggle={handleToggle}
          onDelete={handleDelete}
          onExpand={handleExpand}
          onAction={handleAction}
        />
      ))}
    </div>
  )
}
