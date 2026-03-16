import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";

interface ActionPlanItem {
  recommendationId: string;
  threatId: string;
  threatTitle: string;
  threatSeverity: string;
  threatCategory: string;
  contextualScore: number | null;
  projectedScoreAfterFix: number | null;
  whatIsWrong: string | null;
  fixPreview: string;
  effortTag: string | null;
  roleRequired: string | null;
  status: string;
}

function truncate(text: string | null | undefined, maxLen: number): string {
  if (!text) return "";
  return text.length > maxLen ? text.slice(0, maxLen) + "..." : text;
}

export default function TopActions() {
  const { data: actionPlan = [], isLoading } = useQuery<ActionPlanItem[]>({
    queryKey: ["/api/action-plan"],
    staleTime: 60_000,
  });

  const topThree = actionPlan.slice(0, 3);

  if (isLoading) {
    return (
      <div className="p-4 text-center text-muted-foreground text-sm">
        Carregando acoes...
      </div>
    );
  }

  if (topThree.length === 0) {
    return (
      <div className="p-4 text-center text-muted-foreground text-sm">
        Nenhuma acao prioritaria
      </div>
    );
  }

  return (
    <div className="space-y-3 p-4">
      {topThree.map((item, idx) => (
        <div
          key={item.recommendationId}
          className="flex gap-3 rounded-lg border border-border bg-muted/20 p-4"
        >
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
            {idx + 1}
          </div>
          <div className="flex-1 space-y-1 min-w-0">
            <p className="text-sm font-medium leading-snug">
              {truncate(item.threatTitle, 60)}
            </p>
            {item.whatIsWrong && (
              <p className="text-xs text-muted-foreground">
                {truncate(item.whatIsWrong, 100)}
              </p>
            )}
            {item.fixPreview && (
              <p className="text-xs text-muted-foreground italic">
                {truncate(item.fixPreview, 80)}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              {item.effortTag && (
                <Badge variant="outline" className="text-xs">
                  {item.effortTag}
                </Badge>
              )}
              {item.roleRequired && (
                <Badge variant="outline" className="text-xs">
                  {item.roleRequired}
                </Badge>
              )}
              {item.projectedScoreAfterFix !== null &&
                item.projectedScoreAfterFix !== undefined &&
                item.contextualScore !== null &&
                item.contextualScore !== undefined && (
                  <span className="text-xs font-semibold text-green-500">
                    +
                    {Math.max(
                      0,
                      Math.round(
                        item.projectedScoreAfterFix - item.contextualScore
                      )
                    )}{" "}
                    pts
                  </span>
                )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
