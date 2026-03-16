import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";
import { format } from "date-fns";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { PostureSnapshot } from "@shared/schema";

export default function PostureHero() {
  const { data: snapshots = [], isLoading } = useQuery<PostureSnapshot[]>({
    queryKey: ["/api/posture/history?limit=30"],
    staleTime: 60_000,
  });

  const latest = snapshots[0];
  const previous = snapshots[1];

  const score = latest?.score ?? null;
  const prevScore = previous?.score ?? null;

  const delta = score !== null && prevScore !== null ? score - prevScore : null;

  // Prepare chronological chart data (history is newest-first, reverse for chart)
  const chartData = [...snapshots].reverse().map((s) => ({
    date: format(new Date(s.scoredAt), "dd/MM"),
    score: Math.round(s.score),
  }));

  const getDeltaDisplay = () => {
    if (delta === null || delta === 0) {
      return (
        <span className="flex items-center gap-1 text-muted-foreground text-sm">
          <Minus className="h-4 w-4" />
          sem alteracao
        </span>
      );
    }
    if (delta > 0) {
      return (
        <span className="flex items-center gap-1 text-green-500 text-sm font-medium">
          <ArrowUpRight className="h-4 w-4" />
          +{delta.toFixed(1)}
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1 text-red-500 text-sm font-medium">
        <ArrowDownRight className="h-4 w-4" />
        {delta.toFixed(1)}
      </span>
    );
  };

  const getScoreColor = (s: number) => {
    if (s >= 80) return "text-green-400";
    if (s >= 60) return "text-yellow-400";
    if (s >= 40) return "text-orange-400";
    return "text-red-400";
  };

  if (isLoading) {
    return (
      <div className="p-6 text-center text-muted-foreground text-sm">
        Carregando postura...
      </div>
    );
  }

  return (
    <div className="p-6 space-y-4">
      {/* Score + delta */}
      <div className="flex items-baseline gap-3">
        <span
          className={`text-5xl font-bold ${score !== null ? getScoreColor(score) : "text-muted-foreground"}`}
        >
          {score !== null ? Math.round(score) : "--"}
        </span>
        <span className="text-muted-foreground text-lg">/100</span>
        {getDeltaDisplay()}
      </div>

      {/* Sparkline */}
      {chartData.length > 1 && (
        <ResponsiveContainer width="100%" height={80}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="postureGradient" x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="5%"
                  stopColor="hsl(var(--primary))"
                  stopOpacity={0.3}
                />
                <stop
                  offset="95%"
                  stopColor="hsl(var(--primary))"
                  stopOpacity={0}
                />
              </linearGradient>
            </defs>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--background))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "6px",
                fontSize: "12px",
              }}
              formatter={(value: number) => [value, "Score"]}
            />
            <Area
              type="monotone"
              dataKey="score"
              stroke="hsl(var(--primary))"
              strokeWidth={2}
              fill="url(#postureGradient)"
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}

      {/* Threat counts row */}
      {latest && (
        <div className="flex items-center gap-6 text-sm">
          <span className="text-muted-foreground">
            <span className="font-semibold text-foreground">
              {latest.openThreatCount}
            </span>{" "}
            abertas
          </span>
          {latest.criticalCount > 0 && (
            <span>
              <span
                className="font-semibold"
                style={{ color: "var(--severity-critical)" }}
              >
                {latest.criticalCount}
              </span>{" "}
              <span className="text-muted-foreground">criticas</span>
            </span>
          )}
          {latest.highCount > 0 && (
            <span>
              <span
                className="font-semibold"
                style={{ color: "var(--severity-high)" }}
              >
                {latest.highCount}
              </span>{" "}
              <span className="text-muted-foreground">altas</span>
            </span>
          )}
        </div>
      )}

      {snapshots.length === 0 && (
        <p className="text-sm text-muted-foreground">
          Nenhum snapshot de postura disponivel. Execute uma jornada primeiro.
        </p>
      )}
    </div>
  );
}
