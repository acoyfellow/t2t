"use client"

import { Switch } from "./ui/switch"
import { Avatar, AvatarFallback } from "./ui/avatar"
import { Button } from "./ui/button"
import { ChevronDown, ChevronUp, ExternalLink, X } from "lucide-react"
import type { McpServer } from "@/lib/types"
import { cn } from "@/lib/utils"

interface McpServerItemProps {
  server: McpServer
  onToggle: (id: string) => void
  onDelete: (id: string) => void
  onExpand: (id: string) => void
  onAction: (id: string, action: string) => void
}

export function McpServerItem({ server, onToggle, onDelete, onExpand, onAction }: McpServerItemProps) {
  const getStatusColor = () => {
    switch (server.status) {
      case "active":
        return "bg-accent"
      case "loading":
        return "bg-warning"
      case "error":
        return "bg-destructive"
      default:
        return "bg-muted"
    }
  }

  const getInitials = (name: string) => {
    return name.charAt(0).toUpperCase()
  }

  return (
    <div className="group">
      <div className="px-6 py-4 flex items-center gap-4">
        {/* Avatar with status indicator */}
        <div className="relative">
          <Avatar className="w-12 h-12 bg-secondary">
            <AvatarFallback className="text-secondary-foreground font-medium">
              {getInitials(server.name)}
            </AvatarFallback>
          </Avatar>
          <div
            className={cn("absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-card", getStatusColor())}
          />
        </div>

        {/* Server info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-base font-medium text-card-foreground">{server.name}</h3>
            {server.actions && server.actions.length > 0 && (
              <div className="flex items-center gap-1">
                {server.actions.map((action) => (
                  <Button
                    key={action}
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => onAction(server.id, action)}
                  >
                    {action === "logout" ? "Logout" : action}
                  </Button>
                ))}
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            {server.status === "loading" ? (
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 border-2 border-warning border-t-transparent rounded-full animate-spin" />
                <span>Loading tools</span>
              </div>
            ) : server.status === "error" ? (
              <div className="flex items-center gap-2">
                <span className="text-destructive-foreground">{server.statusMessage || "Error"}</span>
                {server.expandable && (
                  <button
                    onClick={() => onAction(server.id, "show-output")}
                    className="text-primary hover:underline flex items-center gap-1"
                  >
                    Show Output
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
            ) : (
              <>
                {server.toolsCount && <span>{server.toolsCount} tools</span>}
                {server.promptsCount && <span>, {server.promptsCount} prompts</span>}
                {server.resourcesCount && <span>, {server.resourcesCount} resources</span>}
                {server.statusMessage && <span> {server.statusMessage}</span>}
              </>
            )}

            {server.expandable && (
              <button onClick={() => onExpand(server.id)} className="text-muted-foreground hover:text-foreground ml-1">
                {server.expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            )}
          </div>

          {/* Expanded content */}
          {server.expanded && server.expandedContent && (
            <div className="mt-3 pt-3 border-t border-border">
              {server.expandedContent.map((item, index) => (
                <div
                  key={index}
                  className="px-3 py-2 mb-1 bg-secondary/50 rounded text-sm font-mono text-muted-foreground"
                >
                  {item}
                </div>
              ))}
              <button
                onClick={() => onExpand(server.id)}
                className="text-xs text-muted-foreground hover:text-foreground mt-2 flex items-center gap-1"
              >
                Show less
                <ChevronUp className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>

        {/* Toggle switch */}
        <Switch
          checked={server.enabled}
          onCheckedChange={() => onToggle(server.id)}
          className="data-[state=checked]:bg-accent"
        />

        {/* Delete button (shown on hover) */}
        <Button
          variant="ghost"
          size="icon"
          className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 text-muted-foreground hover:text-destructive"
          onClick={() => onDelete(server.id)}
        >
          <X className="w-4 h-4" />
        </Button>
      </div>
    </div>
  )
}
