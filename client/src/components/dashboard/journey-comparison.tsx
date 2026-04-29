import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, ArrowDownRight, Minus } from "lucide-react";
import { format } from "date-fns";
import type { PostureSnapshot } from "@shared/schema";

export default function JourneyComparison() {
  const { data: snapshots = [], isLoading } = useQuery<PostureSnapshot[]>({
    queryKey: ["/api/posture/history?limit=2"],
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="p-6 text-center text-muted-foreground text-sm">
        Carregando comparação...
      </div>
    );
  }

  if (snapshots.length < 2) {
    return (
      <div className="p-6 text-center text-muted-foreground text-sm">
        Dados insuficientes para comparação — execute pelo menos dois testes de jornada
      </div>
    );
  }

  const current = snapshots[0];
  const previous = snapshots[1];

  const scoreDelta = current.score - previous.score;
  const threatDelta = current.openThreatCount - previous.openThreatCount;
  const criticalDelta = current.criticalCount - previous.criticalCount;
  const highDelta = current.highCount - previous.highCount;

  const formatDate = (ts: string | Date) =>
    format(new Date(ts), "dd/MM/yyyy HH:mm");

  const DeltaIcon = ({ delta }: { delta: number }) => {
    if (delta > 0)
      return <ArrowUpRight className="h-4 w-4 inline-block text-green-500" />;
    if (delta < 0)
      return <ArrowDownRight className="h-4 w-4 inline-block text-red-500" />;
    return <Minus className="h-4 w-4 inline-block text-muted-foreground" />;
  };

  // For score: up = good (green); for threat counts: down = good (green)
  const scoreColor = scoreDelta > 0 ? "text-green-500" : scoreDelta < 0 ? "text-red-500" : "text-muted-foreground";
  const threatColor = (delta: number) =>
    delta < 0 ? "text-green-500" : delta > 0 ? "text-red-500" : "text-muted-foreground";

  const summary = () => {
    if (scoreDelta > 0)
      return `Postura melhorou em ${scoreDelta.toFixed(1)} pontos desde a última execução.`;
    if (scoreDelta < 0)
      return `Postura piorou em ${Math.abs(scoreDelta).toFixed(1)} pontos — novas ameaças detectadas.`;
    return "Postura estável desde a última execução.";
  };

  return (
    <div className="p-6 space-y-4">
      {/* Timestamp labels */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>Atual: {formatDate(current.scoredAt)}</span>
        <span>Anterior: {formatDate(previous.scoredAt)}</span>
      </div>

      {/* Score delta row */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">Postura</span>
        <div className="flex items-center gap-2 text-sm font-medium">
          <span>
            {Math.round(previous.score)} &rarr; {Math.round(current.score)}
          </span>
          <span className={scoreColor}>
            <DeltaIcon delta={scoreDelta} />
            {scoreDelta > 0 ? "+" : ""}
            {scoreDelta.toFixed(1)}
          </span>
        </div>
      </div>

      {/* Threat count deltas grid */}
      <div className="grid grid-cols-3 gap-4 pt-2 border-t border-border">
        {/* Ameacas Abertas */}
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Ameaças Abertas</p>
          <p className="text-sm font-medium">
            {previous.openThreatCount} &rarr; {current.openThreatCount}
          </p>
          <p className={`text-xs font-medium flex items-center gap-0.5 ${threatColor(threatDelta)}`}>
            <DeltaIcon delta={-threatDelta} />
            {threatDelta > 0 ? "+" : ""}
            {threatDelta}
          </p>
        </div>

        {/* Críticas */}
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Críticas</p>
          <p className="text-sm font-medium">
            {previous.criticalCount} &rarr; {current.criticalCount}
          </p>
          <p className={`text-xs font-medium flex items-center gap-0.5 ${threatColor(criticalDelta)}`}>
            <DeltaIcon delta={-criticalDelta} />
            {criticalDelta > 0 ? "+" : ""}
            {criticalDelta}
          </p>
        </div>

        {/* Altas */}
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Altas</p>
          <p className="text-sm font-medium">
            {previous.highCount} &rarr; {current.highCount}
          </p>
          <p className={`text-xs font-medium flex items-center gap-0.5 ${threatColor(highDelta)}`}>
            <DeltaIcon delta={-highDelta} />
            {highDelta > 0 ? "+" : ""}
            {highDelta}
          </p>
        </div>
      </div>

      {/* Summary sentence */}
      <p className={`text-sm font-medium pt-2 ${scoreColor}`}>{summary()}</p>
    </div>
  );
}
