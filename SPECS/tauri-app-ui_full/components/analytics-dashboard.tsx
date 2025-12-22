"use client"

import { useState } from "react"
import { Activity, Zap, Mic } from "lucide-react"
import { Card } from "@/components/ui/card"

interface AnalyticsData {
  totalWords: number
  lifetimeAvg: number
  sessionAvg: number
  sessions: number
  hoursActive: number
  recentActivity: number[]
}

export function AnalyticsDashboard() {
  const [data, setData] = useState<AnalyticsData>({
    totalWords: 3342,
    lifetimeAvg: 158.4,
    sessionAvg: 157.5,
    sessions: 215,
    hoursActive: 0.4,
    recentActivity: [45, 52, 38, 65, 48, 55, 42, 58, 63, 51, 47, 59, 68, 72, 61, 54, 48, 52, 66, 95, 88],
  })

  const [isActive, setIsActive] = useState(true)

  return (
    <div className="p-6 space-y-6">
      {/* Subtitle */}
      <p className="text-sm text-muted-foreground">Voice transcription analytics</p>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Total Words */}
        <Card className="p-6 space-y-4 bg-card/50 border-border">
          <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
            <Activity className="w-6 h-6 text-primary" />
          </div>
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Total Words</p>
            <p className="text-5xl font-bold text-foreground tabular-nums">{data.totalWords.toLocaleString()}</p>
          </div>
        </Card>

        {/* Lifetime Average */}
        <Card className="p-6 space-y-4 bg-card/50 border-border">
          <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
            <Zap className="w-6 h-6 text-primary" />
          </div>
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Lifetime Avg</p>
            <div className="flex items-baseline gap-2">
              <p className="text-5xl font-bold text-foreground tabular-nums">{data.lifetimeAvg}</p>
              <p className="text-lg text-muted-foreground">WPM</p>
            </div>
          </div>
        </Card>

        {/* Session Average */}
        <Card className="p-6 space-y-4 bg-card/50 border-border relative">
          {isActive && (
            <div className="absolute top-4 right-4 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/20">
              <span className="text-xs font-medium text-primary">Active</span>
            </div>
          )}
          <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
            <Mic className="w-6 h-6 text-primary" />
          </div>
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Session Avg</p>
            <div className="flex items-baseline gap-2">
              <p className="text-5xl font-bold text-foreground tabular-nums">{data.sessionAvg}</p>
              <p className="text-lg text-muted-foreground">WPM</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="p-6 bg-card/50 border-border">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Sessions</p>
          <p className="text-4xl font-bold text-foreground tabular-nums">{data.sessions}</p>
        </Card>

        <Card className="p-6 bg-card/50 border-border">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Hours Active</p>
          <p className="text-4xl font-bold text-foreground tabular-nums">{data.hoursActive}h</p>
        </Card>
      </div>

      {/* Recent Activity Chart */}
      <Card className="p-6 bg-card/50 border-border">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-6">Recent Activity</p>
        <div className="flex items-end justify-between gap-1 h-48">
          {data.recentActivity.map((value, index) => {
            const maxValue = Math.max(...data.recentActivity)
            const height = (value / maxValue) * 100
            return (
              <div
                key={index}
                className="flex-1 bg-primary/30 rounded-t hover:bg-primary/50 transition-colors cursor-pointer"
                style={{ height: `${height}%` }}
                title={`${value} words`}
              />
            )
          })}
        </div>
        {/* Dashed baseline */}
        <div className="mt-2 border-t-2 border-dashed border-primary/20" />
      </Card>
    </div>
  )
}
