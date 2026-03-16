import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { CheckCircle, ArrowUpRight, ClipboardList } from "lucide-react";

interface ActionPlanItem {
  recommendationId: string;
  threatId: string;
  threatTitle: string;
  threatSeverity: string;
  threatCategory: string | null;
  contextualScore: number | null;
  projectedScoreAfterFix: number | null;
  whatIsWrong: string;
  fixPreview: string;
  effortTag: string | null;
  roleRequired: string | null;
  status: string;
}

function buildQueryString(filters: {
  effortTag: string;
  roleRequired: string;
  category: string;
}): string {
  const params = new URLSearchParams();
  if (filters.effortTag && filters.effortTag !== "all") params.set("effortTag", filters.effortTag);
  if (filters.roleRequired && filters.roleRequired !== "all") params.set("roleRequired", filters.roleRequired);
  if (filters.category && filters.category !== "all") params.set("category", filters.category);
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

function severityColor(severity: string): "destructive" | "secondary" | "outline" | "default" {
  switch (severity) {
    case "critical": return "destructive";
    case "high": return "destructive";
    case "medium": return "secondary";
    default: return "outline";
  }
}

function effortBadgeClass(effortTag: string | null): string {
  switch (effortTag) {
    case "minutes": return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100";
    case "hours": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100";
    case "days": return "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-100";
    case "weeks": return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100";
    default: return "bg-muted text-muted-foreground";
  }
}

export default function ActionPlan() {
  const [, setLocation] = useLocation();
  const [effortTag, setEffortTag] = useState<string>("all");
  const [roleRequired, setRoleRequired] = useState<string>("all");
  const [category, setCategory] = useState<string>("all");

  const filters = { effortTag, roleRequired, category };
  const qs = buildQueryString(filters);

  const { data: items = [], isLoading } = useQuery<ActionPlanItem[]>({
    queryKey: ["/api/action-plan", filters],
    queryFn: async () => {
      const res = await fetch(`/api/action-plan${qs}`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch action plan");
      return res.json();
    },
  });

  function handleCardClick(threatId: string) {
    setLocation(`/threats?highlight=${threatId}`);
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar title="Plano de Acao" subtitle="Acoes de remediacao priorizadas por impacto na postura de seguranca" />
        <main className="flex-1 overflow-y-auto p-6">
          {/* Page header */}
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-1">
              <ClipboardList className="h-6 w-6 text-primary" />
              <h1 className="text-2xl font-bold text-foreground">Plano de Acao</h1>
            </div>
            <p className="text-muted-foreground text-sm">
              Acoes de remediacao priorizadas por impacto na postura de seguranca.
            </p>
          </div>

          {/* Filter bar */}
          <div className="flex flex-wrap gap-3 mb-6">
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Esforco:</span>
              <Select value={effortTag} onValueChange={setEffortTag}>
                <SelectTrigger className="w-[130px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todos</SelectItem>
                  <SelectItem value="minutes">Minutos</SelectItem>
                  <SelectItem value="hours">Horas</SelectItem>
                  <SelectItem value="days">Dias</SelectItem>
                  <SelectItem value="weeks">Semanas</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Funcao:</span>
              <Select value={roleRequired} onValueChange={setRoleRequired}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todos</SelectItem>
                  <SelectItem value="sysadmin">Sysadmin</SelectItem>
                  <SelectItem value="developer">Developer</SelectItem>
                  <SelectItem value="security">Security</SelectItem>
                  <SelectItem value="vendor">Vendor</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Jornada:</span>
              <Select value={category} onValueChange={setCategory}>
                <SelectTrigger className="w-[160px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todas</SelectItem>
                  <SelectItem value="attack_surface">Attack Surface</SelectItem>
                  <SelectItem value="ad_security">AD Security</SelectItem>
                  <SelectItem value="edr_av">EDR / AV</SelectItem>
                  <SelectItem value="web_application">Web Application</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Loading state */}
          {isLoading && (
            <div className="flex items-center justify-center py-16 text-muted-foreground">
              <span>Carregando...</span>
            </div>
          )}

          {/* Empty state */}
          {!isLoading && items.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground gap-3">
              <CheckCircle className="h-12 w-12 text-green-500" />
              <p className="text-lg font-medium text-foreground">Nenhuma acao pendente</p>
              <p className="text-sm">Nenhuma remediacao encontrada com os filtros selecionados.</p>
            </div>
          )}

          {/* Action cards */}
          {!isLoading && items.length > 0 && (
            <div className="space-y-4">
              {items.map((item) => {
                const scoreDelta =
                  item.projectedScoreAfterFix != null && item.contextualScore != null
                    ? item.projectedScoreAfterFix - item.contextualScore
                    : null;

                return (
                  <Card
                    key={item.recommendationId}
                    className="cursor-pointer hover:border-primary/50 transition-colors"
                    onClick={() => handleCardClick(item.threatId)}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between gap-2">
                        <CardTitle className="text-base font-semibold leading-snug">
                          {item.threatTitle}
                        </CardTitle>
                        <div className="flex items-center gap-2 shrink-0">
                          <Badge variant={severityColor(item.threatSeverity)}>
                            {item.threatSeverity}
                          </Badge>
                          {item.contextualScore != null && (
                            <span className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                              Score: {Math.round(item.contextualScore)}
                            </span>
                          )}
                        </div>
                      </div>
                    </CardHeader>

                    <CardContent className="space-y-3">
                      {/* What is wrong */}
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        {item.whatIsWrong}
                      </p>

                      {/* Fix preview */}
                      {item.fixPreview && (
                        <div className="font-mono text-xs bg-muted p-2 rounded leading-relaxed text-foreground">
                          {item.fixPreview}
                        </div>
                      )}

                      {/* Footer row */}
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        {item.effortTag && (
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${effortBadgeClass(item.effortTag)}`}
                          >
                            {item.effortTag}
                          </span>
                        )}
                        {item.roleRequired && (
                          <Badge variant="outline" className="text-xs">
                            {item.roleRequired}
                          </Badge>
                        )}
                        {scoreDelta != null && scoreDelta > 0 && (
                          <span className="inline-flex items-center gap-1 text-xs text-green-600 font-medium ml-auto">
                            <ArrowUpRight className="h-3 w-3" />
                            +{scoreDelta.toFixed(1)} pts
                          </span>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
