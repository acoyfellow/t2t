"use client"

import { useState } from "react"
import { AnalyticsDashboard } from "./analytics-dashboard"
import { McpServerManager } from "./mcp-server-manager"
import { BarChart3, Server } from "lucide-react"

export function UnifiedApp() {
  const [activeTab, setActiveTab] = useState<"analytics" | "servers">("analytics")

  return (
    <div className="min-h-screen bg-background">
      {/* Header with Tabs */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto max-w-6xl px-6">
          <div className="flex items-center justify-between py-4">
            <div className="flex items-center gap-6">
              <h1 className="text-2xl font-bold tracking-tight text-foreground">t2t</h1>

              {/* Tab Navigation */}
              <nav className="flex gap-1">
                <button
                  onClick={() => setActiveTab("analytics")}
                  className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
                    activeTab === "analytics"
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                  }`}
                >
                  <BarChart3 className="w-4 h-4" />
                  Analytics
                </button>
                <button
                  onClick={() => setActiveTab("servers")}
                  className={`flex items-center gap-2 px-4 py-2 rounded-md transition-colors ${
                    activeTab === "servers"
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                  }`}
                >
                  <Server className="w-4 h-4" />
                  MCP Servers
                </button>
              </nav>
            </div>

            {/* Ready Status */}
            {activeTab === "analytics" && (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-sm font-medium text-primary">Ready</span>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto max-w-6xl">
        {activeTab === "analytics" ? <AnalyticsDashboard /> : <McpServerManager />}
      </div>
    </div>
  )
}
