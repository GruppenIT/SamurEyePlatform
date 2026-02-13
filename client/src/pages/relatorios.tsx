import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  BarChart3,
  Shield,
  Globe,
  Server,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { Threat } from "@shared/schema";

interface ThreatTrendDay {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface JourneySummary {
  category: string;
  total: number;
  open: number;
  critical: number;
  high: number;
  resolved: number;
  mttrDays: number | null;
}

interface ADHistoryEntry {
  jobId: string;
  executedAt: string;
  totalTests: number;
  passed: number;
  failed: number;
  criticalFailures: number;
  score: number;
}

interface EDRCoverageEntry {
  jobId: string;
  executedAt: string;
  totalDiscovered: number;
  tested: number;
  protected: number;
  unprotected: number;
  rate: number;
}

interface CategoryStats {
  [category: string]: { open: number; total: number; critical: number; high: number };
}

const categoryLabels: Record<string, string> = {
  attack_surface: "Attack Surface",
  ad_security: "AD Security",
  edr_av: "EDR/AV",
  web_application: "Web Application",
  uncategorized: "Outros",
};

export default function Relatorios() {
  const [period, setPeriod] = useState("30");
  const { connected } = useWebSocket();

  const { data: trend = [] } = useQuery<ThreatTrendDay[]>({
    queryKey: ["/api/reports/threat-trend", period],
    queryFn: async () => {
      const res = await fetch(`/api/reports/threat-trend?period=${period}`, { credentials: "include" });
      return res.json();
    },
  });

  const { data: summary = [] } = useQuery<JourneySummary[]>({
    queryKey: ["/api/reports/summary-by-journey", period],
    queryFn: async () => {
      const res = await fetch(`/api/reports/summary-by-journey?period=${period}`, { credentials: "include" });
      return res.json();
    },
  });

  const { data: categoryStats } = useQuery<CategoryStats>({
    queryKey: ["/api/threats/stats-by-category"],
  });

  const { data: adHistory = [] } = useQuery<ADHistoryEntry[]>({
    queryKey: ["/api/reports/ad-security/history"],
  });

  const { data: edrCoverage = [] } = useQuery<EDRCoverageEntry[]>({
    queryKey: ["/api/reports/edr-coverage"],
  });

  const { data: threats = [] } = useQuery<Threat[]>({
    queryKey: ["/api/threats"],
    select: (data: any) => (Array.isArray(data) ? data : []),
  });

  // Computed stats for overview
  const totalThreats = trend.reduce(
    (sum, d) => sum + d.critical + d.high + d.medium + d.low + d.info,
    0
  );
  const resolvedInPeriod = summary.reduce((sum, s) => sum + s.resolved, 0);
  const avgMttr = summary.filter((s) => s.mttrDays).length > 0
    ? Math.round(
        (summary.filter((s) => s.mttrDays).reduce((sum, s) => sum + (s.mttrDays || 0), 0) /
          summary.filter((s) => s.mttrDays).length) * 10
      ) / 10
    : null;

  // Max value for bar chart scaling
  const maxDayTotal = Math.max(
    1,
    ...trend.map((d) => d.critical + d.high + d.medium + d.low + d.info)
  );

  // Attack surface specific: CVEs from threats
  const asCves = threats
    .filter((t: any) => t.category === "attack_surface" && t.evidence?.cve)
    .reduce((acc: Record<string, any>, t: any) => {
      const cve = t.evidence.cve;
      if (!acc[cve]) {
        acc[cve] = {
          cve,
          cvss: t.evidence?.cvss || t.evidence?.cvssScore || 0,
          hosts: new Set(),
          severity: t.severity,
          status: t.status,
        };
      }
      acc[cve].hosts.add(t.affectedHost || t.evidence?.target || "");
      return acc;
    }, {});

  const topCves = Object.values(asCves)
    .sort((a: any, b: any) => b.cvss - a.cvss)
    .slice(0, 10) as any[];

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar
          title="Relatorios"
          subtitle="Analise historica e metricas por tipo de jornada"
          wsConnected={connected}
        />
        <div className="p-6 overflow-auto h-[calc(100%-4rem)]">
          <Tabs defaultValue="overview" className="space-y-6">
            {/* Header: tabs + period selector */}
            <div className="flex items-center justify-between">
              <TabsList>
                <TabsTrigger value="overview">Visao Geral</TabsTrigger>
                <TabsTrigger value="attack_surface">Attack Surface</TabsTrigger>
                <TabsTrigger value="ad_security">AD Security</TabsTrigger>
                <TabsTrigger value="edr_av">EDR/AV</TabsTrigger>
              </TabsList>
              <Select value={period} onValueChange={setPeriod}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="7">7 dias</SelectItem>
                  <SelectItem value="30">30 dias</SelectItem>
                  <SelectItem value="90">90 dias</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* === TAB: VISAO GERAL === */}
            <TabsContent value="overview" className="space-y-6">
              {/* KPI Cards */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard label="Encontradas no Periodo" value={totalThreats} icon={AlertTriangle} />
                <MetricCard label="Resolvidas" value={resolvedInPeriod} icon={CheckCircle} color="text-green-400" />
                <MetricCard
                  label="MTTR (dias)"
                  value={avgMttr !== null ? avgMttr : "-"}
                  icon={TrendingDown}
                  color="text-primary"
                />
                <MetricCard
                  label="Taxa Resolucao"
                  value={totalThreats > 0 ? `${Math.round((resolvedInPeriod / totalThreats) * 100)}%` : "-"}
                  icon={TrendingUp}
                  color="text-green-400"
                />
              </div>

              {/* Trend Chart (bar chart) */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Tendencia de Ameacas por Severidade</CardTitle>
                </CardHeader>
                <CardContent>
                  {trend.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      Sem dados no periodo selecionado
                    </p>
                  ) : (
                    <div className="space-y-1">
                      <div className="flex items-end gap-[2px] h-32">
                        {trend.map((d, i) => {
                          const total = d.critical + d.high + d.medium + d.low + d.info;
                          const h = (total / maxDayTotal) * 100;
                          return (
                            <div
                              key={i}
                              className="flex-1 flex flex-col justify-end"
                              title={`${d.day}: ${total} ameacas`}
                            >
                              {d.critical > 0 && (
                                <div
                                  style={{
                                    height: `${(d.critical / maxDayTotal) * 100}%`,
                                    backgroundColor: "var(--severity-critical)",
                                  }}
                                  className="rounded-t-sm"
                                />
                              )}
                              {d.high > 0 && (
                                <div
                                  style={{
                                    height: `${(d.high / maxDayTotal) * 100}%`,
                                    backgroundColor: "var(--severity-high)",
                                  }}
                                />
                              )}
                              {d.medium > 0 && (
                                <div
                                  style={{
                                    height: `${(d.medium / maxDayTotal) * 100}%`,
                                    backgroundColor: "var(--severity-medium)",
                                  }}
                                />
                              )}
                              {d.low + d.info > 0 && (
                                <div
                                  style={{
                                    height: `${((d.low + d.info) / maxDayTotal) * 100}%`,
                                    backgroundColor: "var(--severity-low)",
                                  }}
                                  className="rounded-b-sm"
                                />
                              )}
                            </div>
                          );
                        })}
                      </div>
                      <div className="flex justify-between text-[10px] text-muted-foreground">
                        <span>{trend[0]?.day.slice(5)}</span>
                        <span>{trend[trend.length - 1]?.day.slice(5)}</span>
                      </div>
                      <div className="flex gap-4 pt-2 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "var(--severity-critical)" }} /> Critica
                        </span>
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "var(--severity-high)" }} /> Alta
                        </span>
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "var(--severity-medium)" }} /> Media
                        </span>
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "var(--severity-low)" }} /> Baixa
                        </span>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Summary by Journey */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Comparativo por Tipo de Jornada</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Tipo</TableHead>
                        <TableHead className="text-right">Abertas</TableHead>
                        <TableHead className="text-right">Criticas</TableHead>
                        <TableHead className="text-right">Resolvidas</TableHead>
                        <TableHead className="text-right">MTTR</TableHead>
                        <TableHead className="text-right">Total</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {summary.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center text-muted-foreground">
                            Sem dados
                          </TableCell>
                        </TableRow>
                      ) : (
                        summary
                          .filter((s) => s.total > 0)
                          .sort((a, b) => b.open - a.open)
                          .map((s) => (
                            <TableRow key={s.category}>
                              <TableCell className="font-medium">
                                {categoryLabels[s.category] || s.category}
                              </TableCell>
                              <TableCell className="text-right">{s.open}</TableCell>
                              <TableCell className="text-right">
                                {s.critical > 0 ? (
                                  <span className="text-destructive font-medium">{s.critical}</span>
                                ) : (
                                  "0"
                                )}
                              </TableCell>
                              <TableCell className="text-right">{s.resolved}</TableCell>
                              <TableCell className="text-right text-muted-foreground">
                                {s.mttrDays ? `${s.mttrDays}d` : "-"}
                              </TableCell>
                              <TableCell className="text-right text-muted-foreground">{s.total}</TableCell>
                            </TableRow>
                          ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            {/* === TAB: ATTACK SURFACE === */}
            <TabsContent value="attack_surface" className="space-y-6">
              {/* KPIs */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard
                  label="Ameacas Abertas"
                  value={categoryStats?.attack_surface?.open || 0}
                  icon={Globe}
                  color={
                    (categoryStats?.attack_surface?.critical || 0) > 0
                      ? "text-destructive"
                      : "text-muted-foreground"
                  }
                />
                <MetricCard
                  label="Criticas"
                  value={categoryStats?.attack_surface?.critical || 0}
                  icon={AlertTriangle}
                  color="text-destructive"
                />
                <MetricCard
                  label="CVEs Detectadas"
                  value={Object.keys(asCves).length}
                  icon={Shield}
                  color="text-orange-400"
                />
                <MetricCard
                  label="Total"
                  value={categoryStats?.attack_surface?.total || 0}
                  icon={BarChart3}
                />
              </div>

              {/* Top CVEs */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Top 10 CVEs Detectadas</CardTitle>
                </CardHeader>
                <CardContent>
                  {topCves.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      Nenhuma CVE detectada
                    </p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>CVE</TableHead>
                          <TableHead className="text-right">CVSS</TableHead>
                          <TableHead className="text-right">Hosts</TableHead>
                          <TableHead>Severidade</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {topCves.map((cve: any) => (
                          <TableRow key={cve.cve}>
                            <TableCell className="font-mono text-xs">{cve.cve}</TableCell>
                            <TableCell className="text-right font-medium">
                              {Number(cve.cvss).toFixed(1)}
                            </TableCell>
                            <TableCell className="text-right">{cve.hosts.size}</TableCell>
                            <TableCell>
                              <Badge
                                style={getSeverityStyle(cve.severity)}
                                className="text-xs"
                              >
                                {cve.severity}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === TAB: AD SECURITY === */}
            <TabsContent value="ad_security" className="space-y-6">
              {/* Score Hero */}
              {adHistory.length > 0 && (
                <Card>
                  <CardContent className="py-5 px-6">
                    <div className="flex items-center gap-6">
                      <div>
                        <div className="flex items-baseline gap-2">
                          <span
                            className={`text-3xl font-bold ${
                              adHistory[0].score >= 80
                                ? "text-green-400"
                                : adHistory[0].score >= 60
                                ? "text-yellow-400"
                                : "text-red-400"
                            }`}
                          >
                            {adHistory[0].score}
                          </span>
                          <span className="text-sm text-muted-foreground">/100</span>
                        </div>
                        <p className="text-xs text-muted-foreground">Score AD (ultima execucao)</p>
                      </div>
                      <div className="flex-1">
                        <div className="flex items-end gap-1 h-12">
                          {adHistory
                            .slice()
                            .reverse()
                            .map((h, i) => (
                              <div
                                key={i}
                                className="flex-1 rounded-sm"
                                style={{
                                  height: `${h.score}%`,
                                  backgroundColor:
                                    h.score >= 80
                                      ? "rgb(74, 222, 128)"
                                      : h.score >= 60
                                      ? "rgb(250, 204, 21)"
                                      : "rgb(248, 113, 113)",
                                  opacity: 0.7,
                                }}
                                title={`${new Date(h.executedAt).toLocaleDateString("pt-BR")}: ${h.score}/100`}
                              />
                            ))}
                        </div>
                      </div>
                      <div className="text-right text-sm text-muted-foreground">
                        <p>{adHistory[0].passed}/{adHistory[0].totalTests} testes passando</p>
                        <p>{adHistory[0].criticalFailures} falhas criticas</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* History Table */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Historico de Execucoes</CardTitle>
                </CardHeader>
                <CardContent>
                  {adHistory.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      Nenhuma execucao de AD Security encontrada
                    </p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Data</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                          <TableHead className="text-right">Pass</TableHead>
                          <TableHead className="text-right">Fail</TableHead>
                          <TableHead className="text-right">Criticas</TableHead>
                          <TableHead className="text-right">Total</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {adHistory.map((h) => (
                          <TableRow key={h.jobId}>
                            <TableCell className="text-xs">
                              {new Date(h.executedAt).toLocaleString("pt-BR")}
                            </TableCell>
                            <TableCell className="text-right font-medium">
                              <span
                                className={
                                  h.score >= 80
                                    ? "text-green-400"
                                    : h.score >= 60
                                    ? "text-yellow-400"
                                    : "text-red-400"
                                }
                              >
                                {h.score}%
                              </span>
                            </TableCell>
                            <TableCell className="text-right text-green-400">{h.passed}</TableCell>
                            <TableCell className="text-right text-red-400">{h.failed}</TableCell>
                            <TableCell className="text-right">
                              {h.criticalFailures > 0 ? (
                                <span className="text-destructive font-medium">{h.criticalFailures}</span>
                              ) : (
                                "0"
                              )}
                            </TableCell>
                            <TableCell className="text-right text-muted-foreground">
                              {h.totalTests}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* === TAB: EDR/AV === */}
            <TabsContent value="edr_av" className="space-y-6">
              {/* Hero Rate */}
              {edrCoverage.length > 0 && (
                <Card>
                  <CardContent className="py-6 px-6 text-center">
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                      Taxa de Protecao (ultima execucao)
                    </p>
                    <span
                      className={`text-5xl font-bold ${
                        edrCoverage[0].rate >= 95
                          ? "text-green-400"
                          : edrCoverage[0].rate >= 80
                          ? "text-yellow-400"
                          : "text-red-400"
                      }`}
                    >
                      {edrCoverage[0].rate}%
                    </span>
                    <p className="text-sm text-muted-foreground mt-2">
                      {edrCoverage[0].protected} de {edrCoverage[0].tested} endpoints detectaram EICAR
                    </p>
                    {edrCoverage[0].unprotected > 0 && (
                      <p className="text-sm text-destructive mt-1">
                        {edrCoverage[0].unprotected} endpoints desprotegidos
                      </p>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Coverage History */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Historico de Cobertura</CardTitle>
                </CardHeader>
                <CardContent>
                  {edrCoverage.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-8">
                      Nenhum teste EDR/AV encontrado
                    </p>
                  ) : (
                    <>
                      {/* Bar chart */}
                      <div className="flex items-end gap-2 h-24 mb-4">
                        {edrCoverage
                          .slice()
                          .reverse()
                          .map((e, i) => {
                            const maxTested = Math.max(1, ...edrCoverage.map((c) => c.tested));
                            return (
                              <div
                                key={i}
                                className="flex-1 flex flex-col justify-end gap-[1px]"
                                title={`${new Date(e.executedAt).toLocaleDateString("pt-BR")}: ${e.rate}%`}
                              >
                                <div
                                  className="rounded-t-sm"
                                  style={{
                                    height: `${(e.protected / maxTested) * 100}%`,
                                    backgroundColor: "rgb(74, 222, 128)",
                                    minHeight: e.protected > 0 ? "2px" : "0",
                                  }}
                                />
                                <div
                                  className="rounded-b-sm"
                                  style={{
                                    height: `${(e.unprotected / maxTested) * 100}%`,
                                    backgroundColor: "rgb(248, 113, 113)",
                                    minHeight: e.unprotected > 0 ? "2px" : "0",
                                  }}
                                />
                              </div>
                            );
                          })}
                      </div>
                      <div className="flex gap-4 text-xs text-muted-foreground mb-4">
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm bg-green-400" /> Protegidos
                        </span>
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-sm bg-red-400" /> Desprotegidos
                        </span>
                      </div>

                      {/* Table */}
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Data</TableHead>
                            <TableHead className="text-right">Descobertos</TableHead>
                            <TableHead className="text-right">Testados</TableHead>
                            <TableHead className="text-right">Protegidos</TableHead>
                            <TableHead className="text-right">Taxa</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {edrCoverage.map((e) => (
                            <TableRow key={e.jobId}>
                              <TableCell className="text-xs">
                                {new Date(e.executedAt).toLocaleString("pt-BR")}
                              </TableCell>
                              <TableCell className="text-right">{e.totalDiscovered}</TableCell>
                              <TableCell className="text-right">{e.tested}</TableCell>
                              <TableCell className="text-right text-green-400">{e.protected}</TableCell>
                              <TableCell className="text-right">
                                <span
                                  className={`font-medium ${
                                    e.rate >= 95
                                      ? "text-green-400"
                                      : e.rate >= 80
                                      ? "text-yellow-400"
                                      : "text-red-400"
                                  }`}
                                >
                                  {e.rate}%
                                </span>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  color = "text-muted-foreground",
}: {
  label: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color?: string;
}) {
  return (
    <Card>
      <CardContent className="py-4 px-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <span className={`text-2xl font-bold ${color} mt-1 block`}>{value}</span>
          </div>
          <Icon className={`h-5 w-5 ${color} opacity-50`} />
        </div>
      </CardContent>
    </Card>
  );
}

function getSeverityStyle(severity: string): React.CSSProperties {
  const map: Record<string, { bg: string; color: string }> = {
    critical: { bg: "var(--severity-critical)", color: "#fff" },
    high: { bg: "var(--severity-high)", color: "#fff" },
    medium: { bg: "var(--severity-medium)", color: "var(--background)" },
    low: { bg: "var(--severity-low)", color: "#fff" },
  };
  const s = map[severity] || { bg: "var(--muted)", color: "var(--muted-foreground)" };
  return { backgroundColor: s.bg, color: s.color };
}
