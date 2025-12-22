"use client"

import { useState } from "react"
import { McpServerList } from "./mcp-server-list"
import { AddServerDialog } from "./add-server-dialog"
import { Plus } from "lucide-react"

export function McpServerManager() {
  const [showAddDialog, setShowAddDialog] = useState(false)

  return (
    <div className="p-6 space-y-6">
      {/* Subtitle */}
      <p className="text-sm text-muted-foreground">Manage your MCP servers</p>

      {/* Server List */}
      <div className="bg-card/50 border border-border rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-border">
          <h2 className="text-lg font-medium text-card-foreground">Installed MCP Servers</h2>
        </div>

        <McpServerList />

        {/* Add New Server Button */}
        <button
          onClick={() => setShowAddDialog(true)}
          className="w-full px-6 py-4 flex items-center gap-4 hover:bg-secondary/50 transition-colors border-t border-border"
        >
          <div className="w-12 h-12 rounded-full bg-secondary flex items-center justify-center">
            <Plus className="w-5 h-5 text-secondary-foreground" />
          </div>
          <div className="flex-1 text-left">
            <div className="text-base font-medium text-card-foreground">New MCP Server</div>
            <div className="text-sm text-muted-foreground">Add a Custom MCP Server</div>
          </div>
        </button>
      </div>

      <AddServerDialog open={showAddDialog} onOpenChange={setShowAddDialog} />
    </div>
  )
}
