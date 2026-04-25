import { apiFetch } from "@/lib/queryClient";
import { useState, useMemo } from "react";
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
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import {
  AlertTriangle,
  CheckCircle,
  TrendingDown,
  TrendingUp,
  Shield,
  Globe,
  Server,
  Cpu,
  Code2,
  Activity,
  Clock,
  XCircle,
  Zap,
} from "lucide-react";
import { OWASP_API_CATEGORY_LABELS } from "@shared/owaspApiCategories";

// ─── Types ──────────────────────────────────────────────────────────────────

interface ThreatTrendDay {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
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

interface AttackSurfaceStats {
  services: { service: string; total: number; critical: number; high: number; medium: number; low: number; host_count: number }[];
  topCves: { cve: string; cvss: number; host_count: number; severity: string; open_count: number }[];
  severity: { severity: string; count: number }[];
}

interface WebAppStats {
  severity: { severity: string; count: number }[];
  topFindings: { rule: string; total: number; high_sev: number; open_count: number; top_severity: string }[];
}

interface ApiSecurityStats {
  byCategory: { category: string; severity: string; status: string; count: number }[];
  trend: ThreatTrendDay[];
  summary: { total: number; critical: number; high: number; open_count: number };
}

interface ApiInventoryEntry {
  apiId: string;
  baseUrl: string;
  apiType: string;
  specUrl: string | null;
  assetId: string | null;
  assetName: string | null;
  endpointCount: number;
  unauthCount: number;
  authCount: number;
  unknownAuthCount: number;
  methods: { GET: number; POST: number; PUT: number; PATCH: number; DELETE: number; OTHER: number };
  lastScannedAt: string | null;
  openFindingCount: number;
  highRiskCount: number;
}

interface ApiInventory {
  apis: ApiInventoryEntry[];
  methodTotals: Record<string, number>;
  recentDiscoveries: { method: string; path: string; baseUrl: string; apiId: string; assetName: string | null; discoveredAt: string }[];
  totals: { total_apis: number; total_endpoints: number; unauth_endpoints: number; auth_endpoints: number; unknown_auth_endpoints: number };
  sourceCounts: { source: string; count: number }[];
}

interface JourneyHistoryEntry {
  jobId: string;
  startedAt: string;
  finishedAt: string | null;
  status: string;
  progress: number;
  error: string | null;
  journeyName: string;
  journeyId: string;
  durationSecs: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

const SEV_PT: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Médio",
  low: "Baixo",
  info: "Info",
};

const STATUS_CX: Record<string, string> = {
  completed: "text-green-400",
  failed: "text-destructive",
  running: "text-blue-400",
  pending: "text-muted-foreground",
  queued: "text-yellow-400",
};

const OWASP_API_KEYS = Object.keys(OWASP_API_CATEGORY_LABELS) as (keyof typeof OWASP_API_CATEGORY_LABELS)[];

// ─── Small helpers ────────────────────────────────────────────────────────────

function PeriodSelector({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="w-32">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="7">7 dias</SelectItem>
        <SelectItem value="30">30 dias</SelectItem>
        <SelectItem value="90">90 dias</SelectItem>
        <SelectItem value="180">6 meses</SelectItem>
      </SelectContent>
    </Select>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  color = "text-muted-foreground",
  sub,
}: {
  label: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color?: string;
  sub?: string;
}) {
  return (
    <Card>
      <CardContent className="py-4 px-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <span className={`text-2xl font-bold ${color} mt-1 block`}>{value}</span>
            {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
          </div>
          <Icon className={`h-5 w-5 ${color} opacity-40`} />
        </div>
      </CardContent>
    </Card>
  );
}

function Empty({ msg = "Sem dados no período selecionado" }: { msg?: string }) {
  return <p className="text-sm text-muted-foreground text-center py-10">{msg}</p>;
}

function SeverityBar({ critical = 0, high = 0, medium = 0, low = 0 }: { critical?: number; high?: number; medium?: number; low?: number }) {
  const total = critical + high + medium + low;
  if (total === 0) return <div className="h-1.5 w-full rounded bg-muted" />;
  return (
    <div className="flex h-1.5 w-full rounded overflow-hidden">
      {critical > 0 && <div style={{ width: `${(critical / total) * 100}%`, backgroundColor: SEV_COLORS.critical }} />}
      {high > 0 && <div style={{ width: `${(high / total) * 100}%`, backgroundColor: SEV_COLORS.high }} />}
      {medium > 0 && <div style={{ width: `${(medium / total) * 100}%`, backgroundColor: SEV_COLORS.medium }} />}
      {low > 0 && <div style={{ width: `${(low / total) * 100}%`, backgroundColor: SEV_COLORS.low }} />}
    </div>
  );
}

function fmtDay(d: string) {
  return d.slice(5);
}

function fmtDuration(secs: number) {
  if (!secs || secs <= 0) return "-";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function getSeverityStyle(sev: string): React.CSSProperties {
  const c = SEV_COLORS[sev as keyof typeof SEV_COLORS] ?? SEV_COLORS.info;
  return { backgroundColor: c, color: "#fff" };
}

// Generic heat map grid
function HeatMap({
  rowLabels,
  colLabels,
  data,
  getColor,
}: {
  rowLabels: string[];
  colLabels: string[];
  data: Record<string, Record<string, number>>;
  getColor: (col: string, intensity: number) => string;
}) {
  if (rowLabels.length === 0) return <Empty />;
  const allVals = rowLabels.flatMap((r) => colLabels.map((c) => data[r]?.[c] ?? 0));
  const maxVal = Math.max(1, ...allVals);
  return (
    <div className="overflow-x-auto">
      <table className="text-xs w-full">
        <thead>
          <tr>
            <th className="text-left text-muted-foreground pb-2 pr-4 font-normal w-32" />
            {colLabels.map((c) => (
              <th key={c} className="text-center text-muted-foreground pb-2 px-1 font-normal capitalize min-w-[60px]">
                {SEV_PT[c] ?? c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rowLabels.map((row) => (
            <tr key={row}>
              <td className="text-muted-foreground pr-4 py-0.5 truncate max-w-[128px] text-[11px]">{row}</td>
              {colLabels.map((col) => {
                const v = data[row]?.[col] ?? 0;
                const intensity = v / maxVal;
                return (
                  <td key={col} className="px-1 py-0.5 text-center">
                    <div
                      className="w-10 h-6 rounded mx-auto flex items-center justify-center text-[10px] font-semibold transition-colors"
                      style={{
                        backgroundColor: getColor(col, intensity),
                        color: intensity > 0.35 ? "#fff" : "var(--muted-foreground)",
                      }}
                      title={`${row} / ${SEV_PT[col] ?? col}: ${v}`}
                    >
                      {v > 0 ? v : ""}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JourneyHistory({ history }: { history: JourneyHistoryEntry[] }) {
  if (history.length === 0) return <Empty msg="Nenhuma execução encontrada no período" />;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Jornada</TableHead>
          <TableHead>Início</TableHead>
          <TableHead>Duração</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {history.map((h) => (
          <TableRow key={h.jobId}>
            <TableCell className="font-medium text-sm max-w-[200px] truncate">{h.journeyName}</TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {h.startedAt ? new Date(h.startedAt).toLocaleString("pt-BR") : "-"}
            </TableCell>
            <TableCell className="text-xs">{fmtDuration(h.durationSecs)}</TableCell>
            <TableCell>
              <Badge variant="outline" className={`text-xs capitalize ${STATUS_CX[h.status] ?? ""}`}>
                {h.status}
              </Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// Custom tooltip (shared)
function SevTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-popover border border-border rounded-md px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-foreground mb-1">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.fill || p.stroke }} />
          <span className="text-muted-foreground">{SEV_PT[p.dataKey] ?? p.dataKey}:</span>
          <span className="font-medium">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function Relatorios() {
  const [period, setPeriod] = useState("30");
  const [selectedApiId, setSelectedApiId] = useState<string>("all");
  const { connected } = useWebSocket();

  // ── Shared queries ───────────────────────────────────────────────────────
  const { data: trend = [] } = useQuery<ThreatTrendDay[]>({
    queryKey: ["/api/reports/threat-trend", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/threat-trend?period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: summary = [] } = useQuery<JourneySummary[]>({
    queryKey: ["/api/reports/summary-by-journey", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/summary-by-journey?period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: adHistory = [] } = useQuery<ADHistoryEntry[]>({
    queryKey: ["/api/reports/ad-security/history"],
  });

  const { data: edrCoverage = [] } = useQuery<EDRCoverageEntry[]>({
    queryKey: ["/api/reports/edr-coverage"],
  });

  const { data: asStats } = useQuery<AttackSurfaceStats>({
    queryKey: ["/api/reports/attack-surface/stats", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/attack-surface/stats?period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: asTrend = [] } = useQuery<ThreatTrendDay[]>({
    queryKey: ["/api/reports/category-trend/attack_surface", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/category-trend?category=attack_surface&period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: webStats } = useQuery<WebAppStats>({
    queryKey: ["/api/reports/web-application/stats", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/web-application/stats?period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: webTrend = [] } = useQuery<ThreatTrendDay[]>({
    queryKey: ["/api/reports/category-trend/web_application", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/category-trend?category=web_application&period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const apiStatsApiId = selectedApiId !== "all" ? selectedApiId : undefined;
  const { data: apiStats } = useQuery<ApiSecurityStats>({
    queryKey: ["/api/reports/api-security/stats", period, apiStatsApiId],
    queryFn: async () => {
      const params = new URLSearchParams({ period });
      if (apiStatsApiId) params.set("apiId", apiStatsApiId);
      const r = await apiFetch(`/api/reports/api-security/stats?${params}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: apiInventory } = useQuery<ApiInventory>({
    queryKey: ["/api/reports/api-security/inventory", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/api-security/inventory?period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: histAS = [] } = useQuery<JourneyHistoryEntry[]>({
    queryKey: ["/api/reports/journey-history/attack_surface", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/journey-history?type=attack_surface&period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: histWeb = [] } = useQuery<JourneyHistoryEntry[]>({
    queryKey: ["/api/reports/journey-history/web_application", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/journey-history?type=web_application&period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  const { data: histApi = [] } = useQuery<JourneyHistoryEntry[]>({
    queryKey: ["/api/reports/journey-history/api_security", period],
    queryFn: async () => {
      const r = await apiFetch(`/api/reports/journey-history?type=api_security&period=${period}`, { credentials: "include" });
      return r.json();
    },
  });

  // ── Computed: Overview ───────────────────────────────────────────────────
  const totalThreats = trend.reduce((s, d) => s + (d.critical || 0) + (d.high || 0) + (d.medium || 0) + (d.low || 0), 0);
  const resolvedInPeriod = summary.reduce((s, x) => s + (x.resolved || 0), 0);
  const criticalOpen = summary.reduce((s, x) => s + (x.critical || 0), 0);
  const avgMttr =
    summary.filter((s) => s.mttrDays).length > 0
      ? Math.round(
          (summary.filter((s) => s.mttrDays).reduce((s, x) => s + (x.mttrDays || 0), 0) /
            summary.filter((s) => s.mttrDays).length) *
            10,
        ) / 10
      : null;

  const summaryBarData = summary
    .filter((s) => s.total > 0)
    .map((s) => ({
      name: { attack_surface: "Attack Surface", ad_security: "AD Sec", edr_av: "EDR/AV", web_application: "Web App", api_security: "API Sec" }[s.category] || s.category,
      abertas: s.open,
      criticas: s.critical,
      resolvidas: s.resolved,
    }));

  const overviewPieData = summary
    .filter((s) => s.open > 0)
    .map((s) => ({
      name: { attack_surface: "Attack Surface", ad_security: "AD Sec", edr_av: "EDR/AV", web_application: "Web App", api_security: "API Sec" }[s.category] || s.category,
      value: s.open,
    }));

  const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6"];

  // ── Computed: Attack Surface ─────────────────────────────────────────────
  const asServices = asStats?.services ?? [];
  const asTopCves = asStats?.topCves ?? [];
  const asSeverityPie = (asStats?.severity ?? []).map((s) => ({ name: s.severity, value: s.count }));
  const asTotalOpen = (asStats?.severity ?? []).reduce((sum, s) => sum + s.count, 0);

  // Heat map: service × severity
  const asHeatRows = asServices.slice(0, 10).map((s) => s.service);
  const asHeatCols = ["critical", "high", "medium", "low"];
  const asHeatData: Record<string, Record<string, number>> = {};
  for (const s of asServices) {
    asHeatData[s.service] = { critical: s.critical, high: s.high, medium: s.medium, low: s.low };
  }

  // ── Computed: AD Security ────────────────────────────────────────────────
  const latestAd = adHistory[0];
  const adScoreTrend = adHistory
    .slice()
    .reverse()
    .map((h) => ({
      date: new Date(h.executedAt).toLocaleDateString("pt-BR", { month: "2-digit", day: "2-digit" }),
      score: h.score,
      passed: h.passed,
      failed: h.failed,
    }));

  // ── Computed: EDR/AV ─────────────────────────────────────────────────────
  const latestEdr = edrCoverage[0];
  const edrTrend = edrCoverage
    .slice()
    .reverse()
    .map((e) => ({
      date: new Date(e.executedAt).toLocaleDateString("pt-BR", { month: "2-digit", day: "2-digit" }),
      protegidos: e.protected,
      desprotegidos: e.unprotected,
      taxa: e.rate,
    }));

  // ── Computed: Web Application ────────────────────────────────────────────
  const webSeverityPie = (webStats?.severity ?? []).map((s) => ({ name: s.severity, value: s.count }));
  const webTotal = (webStats?.severity ?? []).reduce((s, x) => s + x.count, 0);
  const webOpenCount = summary.find((s) => s.category === "web_application")?.open ?? 0;
  const webCritical = summary.find((s) => s.category === "web_application")?.critical ?? 0;

  // ── Computed: API Security ───────────────────────────────────────────────
  const apiSummary = apiStats?.summary ?? { total: 0, critical: 0, high: 0, open_count: 0 };
  const apiByCategory = apiStats?.byCategory ?? [];
  const apiOwasp = OWASP_API_KEYS.map((key) => {
    const entries = apiByCategory.filter((b) => b.category === key);
    const info = OWASP_API_CATEGORY_LABELS[key];
    return {
      code: info.codigo,
      label: info.titulo,
      total: entries.reduce((s, e) => s + e.count, 0),
      critical: entries.filter((e) => e.severity === "critical").reduce((s, e) => s + e.count, 0),
      high: entries.filter((e) => e.severity === "high").reduce((s, e) => s + e.count, 0),
      medium: entries.filter((e) => e.severity === "medium").reduce((s, e) => s + e.count, 0),
      low: entries.filter((e) => e.severity === "low").reduce((s, e) => s + e.count, 0),
      open: entries.filter((e) => e.status === "open").reduce((s, e) => s + e.count, 0),
    };
  });
  const apiOwaspFiltered = apiOwasp.filter((c) => c.total > 0);
  const apiSevPie = ["critical", "high", "medium", "low"]
    .map((sev) => ({
      name: sev,
      value: apiByCategory.filter((b) => b.severity === sev).reduce((s, e) => s + e.count, 0),
    }))
    .filter((x) => x.value > 0);

  const uniqueApiCategories = new Set(apiByCategory.filter((b) => b.count > 0).map((b) => b.category)).size;

  // ── Computed: API Inventory ──────────────────────────────────────────────
  const inventoryApis = apiInventory?.apis ?? [];
  const inventoryTotals = apiInventory?.totals ?? { total_apis: 0, total_endpoints: 0, unauth_endpoints: 0, auth_endpoints: 0, unknown_auth_endpoints: 0 };
  const recentDiscoveries = apiInventory?.recentDiscoveries ?? [];
  const methodTotalsData = useMemo(() => {
    const mt = apiInventory?.methodTotals ?? {};
    return Object.entries(mt).map(([method, count]) => ({ method, count })).sort((a, b) => b.count - a.count);
  }, [apiInventory]);

  const authCoveragePie = useMemo(() => {
    const t = inventoryTotals;
    const data = [
      { name: "autenticados", value: t.auth_endpoints },
      { name: "sem_auth", value: t.unauth_endpoints },
      { name: "desconhecido", value: t.unknown_auth_endpoints },
    ].filter((x) => x.value > 0);
    return data;
  }, [inventoryTotals]);

  const sourceLabels: Record<string, string> = { spec: "Especificação OAS", crawler: "Agente de Rastreio", kiterunner: "Agente de Enumeração", httpx: "Agente HTTP" };
  const SOURCE_COLORS: Record<string, string> = { spec: "#3b82f6", crawler: "#8b5cf6", kiterunner: "#f59e0b", httpx: "#22c55e" };
  const AUTH_COLORS: Record<string, string> = { autenticados: "#22c55e", sem_auth: "#ef4444", desconhecido: "#6b7280" };
  const AUTH_PT: Record<string, string> = { autenticados: "Autenticados", sem_auth: "Sem Auth", desconhecido: "Desconhecido" };

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar
          title="Relatórios"
          subtitle="Análise histórica e métricas por tipo de jornada"
          wsConnected={connected}
        />
        <div className="p-6 overflow-auto h-[calc(100%-4rem)]">
          <Tabs defaultValue="overview" className="space-y-6">
            {/* ── Header: tabs + period selector ── */}
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <TabsList className="flex-wrap h-auto gap-1">
                <TabsTrigger value="overview">Visão Geral</TabsTrigger>
                <TabsTrigger value="attack_surface">Attack Surface</TabsTrigger>
                <TabsTrigger value="ad_security">AD Security</TabsTrigger>
                <TabsTrigger value="edr_av">EDR/AV</TabsTrigger>
                <TabsTrigger value="web_application">Web Application</TabsTrigger>
                <TabsTrigger value="api_discovery">Descoberta de APIs</TabsTrigger>
                <TabsTrigger value="api_security">Segurança de APIs</TabsTrigger>
              </TabsList>
              <PeriodSelector value={period} onChange={setPeriod} />
            </div>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: VISÃO GERAL                                             */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="overview" className="space-y-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard label="Ameaças no Período" value={totalThreats} icon={AlertTriangle} color={totalThreats > 0 ? "text-orange-400" : "text-muted-foreground"} />
                <MetricCard label="Críticas Abertas" value={criticalOpen} icon={Zap} color={criticalOpen > 0 ? "text-destructive" : "text-muted-foreground"} />
                <MetricCard label="Resolvidas" value={resolvedInPeriod} icon={CheckCircle} color="text-green-400" />
                <MetricCard
                  label="MTTR Médio"
                  value={avgMttr !== null ? `${avgMttr}d` : "-"}
                  icon={Clock}
                  color="text-primary"
                  sub="tempo médio de resolução"
                />
              </div>

              {/* Trend area chart */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Tendência de Ameaças por Severidade</CardTitle>
                </CardHeader>
                <CardContent>
                  {trend.length === 0 ? (
                    <Empty />
                  ) : (
                    <ResponsiveContainer width="100%" height={200}>
                      <AreaChart data={trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                        <defs>
                          {(["critical", "high", "medium", "low"] as const).map((s) => (
                            <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor={SEV_COLORS[s]} stopOpacity={0.5} />
                              <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0.05} />
                            </linearGradient>
                          ))}
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                        <XAxis dataKey="day" tick={{ fontSize: 10 }} tickFormatter={fmtDay} stroke="var(--muted-foreground)" />
                        <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                        <Tooltip content={<SevTooltip />} />
                        {(["critical", "high", "medium", "low"] as const).map((s) => (
                          <Area
                            key={s}
                            type="monotone"
                            dataKey={s}
                            stackId="1"
                            stroke={SEV_COLORS[s]}
                            fill={`url(#grad-${s})`}
                            strokeWidth={1.5}
                            dot={false}
                          />
                        ))}
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              {/* Journey comparison */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Ameaças por Tipo de Jornada</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {summaryBarData.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={summaryBarData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n: string) => ({ abertas: "Abertas", criticas: "Críticas", resolvidas: "Resolvidas" }[n] || n)} />
                          <Bar dataKey="abertas" fill={SEV_COLORS.high} radius={[2, 2, 0, 0]} />
                          <Bar dataKey="criticas" fill={SEV_COLORS.critical} radius={[2, 2, 0, 0]} />
                          <Bar dataKey="resolvidas" fill="#22c55e" radius={[2, 2, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Distribuição Abertas</CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-col items-center">
                    {overviewPieData.length === 0 ? (
                      <Empty msg="Nenhuma ameaça aberta" />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <PieChart>
                          <Pie data={overviewPieData} cx="50%" cy="50%" innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value">
                            {overviewPieData.map((_, i) => (
                              <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Summary table */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Comparativo por Jornada</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Tipo</TableHead>
                        <TableHead className="text-right">Abertas</TableHead>
                        <TableHead className="text-right">Críticas</TableHead>
                        <TableHead className="text-right">Altas</TableHead>
                        <TableHead className="text-right">Resolvidas</TableHead>
                        <TableHead className="text-right">MTTR</TableHead>
                        <TableHead>Distribuição</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {summary.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={7} className="text-center text-muted-foreground">
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
                                {{ attack_surface: "Attack Surface", ad_security: "AD Security", edr_av: "EDR/AV", web_application: "Web Application", api_security: "API Security" }[s.category] || s.category}
                              </TableCell>
                              <TableCell className="text-right">{s.open}</TableCell>
                              <TableCell className="text-right">
                                {s.critical > 0 ? <span className="text-destructive font-medium">{s.critical}</span> : "0"}
                              </TableCell>
                              <TableCell className="text-right">
                                {s.high > 0 ? <span className="text-orange-400 font-medium">{s.high}</span> : "0"}
                              </TableCell>
                              <TableCell className="text-right text-green-400">{s.resolved}</TableCell>
                              <TableCell className="text-right text-muted-foreground">
                                {s.mttrDays ? `${s.mttrDays}d` : "-"}
                              </TableCell>
                              <TableCell className="min-w-[120px]">
                                <SeverityBar critical={s.critical} high={s.high} medium={0} low={0} />
                              </TableCell>
                            </TableRow>
                          ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: ATTACK SURFACE                                          */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="attack_surface" className="space-y-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {(() => {
                  const asSummary = summary.find((s) => s.category === "attack_surface");
                  return (
                    <>
                      <MetricCard label="Ameaças Abertas" value={asSummary?.open ?? 0} icon={Globe} color={(asSummary?.critical ?? 0) > 0 ? "text-destructive" : "text-muted-foreground"} />
                      <MetricCard label="Críticas" value={asSummary?.critical ?? 0} icon={AlertTriangle} color="text-destructive" />
                      <MetricCard label="CVEs Detectadas" value={asTopCves.length} icon={Shield} color="text-orange-400" />
                      <MetricCard label="Serviços Expostos" value={asServices.length} icon={Server} color="text-yellow-400" sub={`${asServices.reduce((s, x) => s + x.host_count, 0)} hosts afetados`} />
                    </>
                  );
                })()}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Service bar chart */}
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Top Serviços Expostos</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {asServices.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart
                          data={asServices.slice(0, 10).map((s) => ({
                            name: s.service.length > 16 ? s.service.slice(0, 14) + "…" : s.service,
                            critical: s.critical,
                            high: s.high,
                            medium: s.medium,
                            low: s.low,
                          }))}
                          layout="vertical"
                          margin={{ top: 0, right: 8, left: 10, bottom: 0 }}
                        >
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                          <XAxis type="number" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis type="category" dataKey="name" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" width={90} />
                          <Tooltip content={<SevTooltip />} />
                          <Bar dataKey="critical" stackId="a" fill={SEV_COLORS.critical} />
                          <Bar dataKey="high" stackId="a" fill={SEV_COLORS.high} />
                          <Bar dataKey="medium" stackId="a" fill={SEV_COLORS.medium} />
                          <Bar dataKey="low" stackId="a" fill={SEV_COLORS.low} radius={[0, 2, 2, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Severity pie */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Severidade</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {asSeverityPie.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie data={asSeverityPie} cx="50%" cy="50%" innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value">
                            {asSeverityPie.map((e, i) => (
                              <Cell key={i} fill={SEV_COLORS[e.name as keyof typeof SEV_COLORS] ?? "#888"} />
                            ))}
                          </Pie>
                          <Tooltip formatter={(val, name) => [val, SEV_PT[name as string] ?? name]} />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n) => SEV_PT[n] ?? n} />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Heat map: service × severity */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Mapa de Calor — Serviço × Severidade</CardTitle>
                </CardHeader>
                <CardContent>
                  {asHeatRows.length === 0 ? (
                    <Empty />
                  ) : (
                    <HeatMap
                      rowLabels={asHeatRows}
                      colLabels={asHeatCols}
                      data={asHeatData}
                      getColor={(col, intensity) => {
                        const base = SEV_COLORS[col as keyof typeof SEV_COLORS] ?? "#888";
                        if (intensity === 0) return "transparent";
                        const hex = base.replace("#", "");
                        const r = parseInt(hex.slice(0, 2), 16);
                        const g = parseInt(hex.slice(2, 4), 16);
                        const b = parseInt(hex.slice(4, 6), 16);
                        return `rgba(${r},${g},${b},${0.15 + intensity * 0.85})`;
                      }}
                    />
                  )}
                </CardContent>
              </Card>

              {/* Trend */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Tendência Attack Surface</CardTitle>
                </CardHeader>
                <CardContent>
                  {asTrend.length === 0 ? (
                    <Empty />
                  ) : (
                    <ResponsiveContainer width="100%" height={160}>
                      <AreaChart data={asTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                        <XAxis dataKey="day" tick={{ fontSize: 10 }} tickFormatter={fmtDay} stroke="var(--muted-foreground)" />
                        <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                        <Tooltip content={<SevTooltip />} />
                        {(["critical", "high", "medium", "low"] as const).map((s) => (
                          <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_COLORS[s]} fill={SEV_COLORS[s]} fillOpacity={0.35} strokeWidth={1.5} dot={false} />
                        ))}
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              {/* Top CVEs */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Top CVEs Detectadas</CardTitle>
                </CardHeader>
                <CardContent>
                  {asTopCves.length === 0 ? (
                    <Empty msg="Nenhuma CVE detectada no período" />
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>CVE</TableHead>
                          <TableHead className="text-right">CVSS</TableHead>
                          <TableHead className="text-right">Hosts</TableHead>
                          <TableHead className="text-right">Abertas</TableHead>
                          <TableHead>Severidade</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {asTopCves.map((cve) => (
                          <TableRow key={cve.cve}>
                            <TableCell className="font-mono text-xs">{cve.cve}</TableCell>
                            <TableCell className="text-right font-medium">{Number(cve.cvss).toFixed(1)}</TableCell>
                            <TableCell className="text-right">{cve.host_count}</TableCell>
                            <TableCell className="text-right">{cve.open_count}</TableCell>
                            <TableCell>
                              <Badge style={getSeverityStyle(cve.severity)} className="text-xs">{SEV_PT[cve.severity] ?? cve.severity}</Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              {/* Journey history */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Execuções</CardTitle>
                </CardHeader>
                <CardContent>
                  <JourneyHistory history={histAS} />
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: AD SECURITY                                             */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="ad_security" className="space-y-6">
              {/* Score hero */}
              {latestAd ? (
                <Card>
                  <CardContent className="py-5 px-6">
                    <div className="flex items-center gap-8 flex-wrap">
                      <div className="text-center min-w-[100px]">
                        <div
                          className={`text-5xl font-bold ${
                            latestAd.score >= 80 ? "text-green-400" : latestAd.score >= 60 ? "text-yellow-400" : "text-destructive"
                          }`}
                        >
                          {latestAd.score}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">/100 — última execução</p>
                      </div>
                      <div className="flex-1 min-w-[200px]">
                        <div className="grid grid-cols-3 gap-4 text-center">
                          <div>
                            <div className="text-2xl font-bold text-green-400">{latestAd.passed}</div>
                            <div className="text-xs text-muted-foreground">Passou</div>
                          </div>
                          <div>
                            <div className="text-2xl font-bold text-destructive">{latestAd.failed}</div>
                            <div className="text-xs text-muted-foreground">Falhou</div>
                          </div>
                          <div>
                            <div className={`text-2xl font-bold ${latestAd.criticalFailures > 0 ? "text-destructive" : "text-muted-foreground"}`}>
                              {latestAd.criticalFailures}
                            </div>
                            <div className="text-xs text-muted-foreground">Críticas</div>
                          </div>
                        </div>
                        <div className="mt-3">
                          <SeverityBar critical={latestAd.criticalFailures} high={latestAd.failed - latestAd.criticalFailures} medium={0} low={latestAd.passed} />
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="py-6">
                    <Empty msg="Nenhuma execução de AD Security encontrada" />
                  </CardContent>
                </Card>
              )}

              {/* Score trend + pass/fail chart */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Score ao Longo do Tempo</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {adScoreTrend.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <LineChart data={adScoreTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip formatter={(v) => [`${v}%`, "Score"]} />
                          <Line type="monotone" dataKey="score" stroke="#22c55e" strokeWidth={2} dot={{ r: 3, fill: "#22c55e" }} activeDot={{ r: 5 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Aprovados × Reprovados por Execução</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {adScoreTrend.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={adScoreTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n: string) => ({ passed: "Passou", failed: "Falhou" }[n] || n)} />
                          <Bar dataKey="passed" stackId="a" fill="#22c55e" name="passed" radius={[0, 0, 0, 0]} />
                          <Bar dataKey="failed" stackId="a" fill={SEV_COLORS.critical} name="failed" radius={[2, 2, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* History table */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Execuções</CardTitle>
                </CardHeader>
                <CardContent>
                  {adHistory.length === 0 ? (
                    <Empty msg="Nenhuma execução de AD Security encontrada" />
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Data</TableHead>
                          <TableHead className="text-right">Score</TableHead>
                          <TableHead className="text-right">Passou</TableHead>
                          <TableHead className="text-right">Falhou</TableHead>
                          <TableHead className="text-right">Críticas</TableHead>
                          <TableHead className="text-right">Total</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {adHistory.map((h) => (
                          <TableRow key={h.jobId}>
                            <TableCell className="text-xs">{new Date(h.executedAt).toLocaleString("pt-BR")}</TableCell>
                            <TableCell className="text-right font-medium">
                              <span className={h.score >= 80 ? "text-green-400" : h.score >= 60 ? "text-yellow-400" : "text-destructive"}>
                                {h.score}%
                              </span>
                            </TableCell>
                            <TableCell className="text-right text-green-400">{h.passed}</TableCell>
                            <TableCell className="text-right text-destructive">{h.failed}</TableCell>
                            <TableCell className="text-right">
                              {h.criticalFailures > 0 ? <span className="text-destructive font-medium">{h.criticalFailures}</span> : "0"}
                            </TableCell>
                            <TableCell className="text-right text-muted-foreground">{h.totalTests}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: EDR/AV                                                  */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="edr_av" className="space-y-6">
              {/* Rate hero */}
              {latestEdr ? (
                <Card>
                  <CardContent className="py-6 px-8">
                    <div className="flex items-center gap-10 flex-wrap">
                      <div className="text-center">
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Taxa de Proteção</p>
                        <span
                          className={`text-6xl font-bold ${
                            latestEdr.rate >= 95 ? "text-green-400" : latestEdr.rate >= 80 ? "text-yellow-400" : "text-destructive"
                          }`}
                        >
                          {latestEdr.rate}%
                        </span>
                        <p className="text-xs text-muted-foreground mt-1">última execução</p>
                      </div>
                      <div className="flex-1 min-w-[200px] grid grid-cols-3 gap-4 text-center">
                        <div>
                          <div className="text-2xl font-bold text-muted-foreground">{latestEdr.totalDiscovered}</div>
                          <div className="text-xs text-muted-foreground">Descobertos</div>
                        </div>
                        <div>
                          <div className="text-2xl font-bold text-green-400">{latestEdr.protected}</div>
                          <div className="text-xs text-muted-foreground">Protegidos</div>
                        </div>
                        <div>
                          <div className={`text-2xl font-bold ${latestEdr.unprotected > 0 ? "text-destructive" : "text-muted-foreground"}`}>
                            {latestEdr.unprotected}
                          </div>
                          <div className="text-xs text-muted-foreground">Desprotegidos</div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="py-6">
                    <Empty msg="Nenhum teste EDR/AV encontrado" />
                  </CardContent>
                </Card>
              )}

              {/* Coverage trend + rate line */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Cobertura por Execução</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {edrTrend.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <AreaChart data={edrTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n: string) => ({ protegidos: "Protegidos", desprotegidos: "Desprotegidos" }[n] || n)} />
                          <Area type="monotone" dataKey="protegidos" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.5} />
                          <Area type="monotone" dataKey="desprotegidos" stackId="1" stroke={SEV_COLORS.critical} fill={SEV_COLORS.critical} fillOpacity={0.5} />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Evolução da Taxa de Proteção</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {edrTrend.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <LineChart data={edrTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip formatter={(v) => [`${v}%`, "Taxa"]} />
                          <Line type="monotone" dataKey="taxa" stroke="#22c55e" strokeWidth={2} dot={{ r: 3, fill: "#22c55e" }} activeDot={{ r: 5 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Coverage table */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Cobertura</CardTitle>
                </CardHeader>
                <CardContent>
                  {edrCoverage.length === 0 ? (
                    <Empty msg="Nenhum teste EDR/AV encontrado" />
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Data</TableHead>
                          <TableHead className="text-right">Descobertos</TableHead>
                          <TableHead className="text-right">Testados</TableHead>
                          <TableHead className="text-right">Protegidos</TableHead>
                          <TableHead className="text-right">Desprotegidos</TableHead>
                          <TableHead className="text-right">Taxa</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {edrCoverage.map((e) => (
                          <TableRow key={e.jobId}>
                            <TableCell className="text-xs">{new Date(e.executedAt).toLocaleString("pt-BR")}</TableCell>
                            <TableCell className="text-right">{e.totalDiscovered}</TableCell>
                            <TableCell className="text-right">{e.tested}</TableCell>
                            <TableCell className="text-right text-green-400">{e.protected}</TableCell>
                            <TableCell className="text-right">
                              {e.unprotected > 0 ? <span className="text-destructive">{e.unprotected}</span> : "0"}
                            </TableCell>
                            <TableCell className="text-right">
                              <span className={`font-medium ${e.rate >= 95 ? "text-green-400" : e.rate >= 80 ? "text-yellow-400" : "text-destructive"}`}>
                                {e.rate}%
                              </span>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: WEB APPLICATION                                         */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="web_application" className="space-y-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard label="Ameaças Abertas" value={webOpenCount} icon={Code2} color={webCritical > 0 ? "text-destructive" : "text-muted-foreground"} />
                <MetricCard label="Críticas" value={webCritical} icon={AlertTriangle} color="text-destructive" />
                <MetricCard label="Total no Período" value={webTotal} icon={Activity} />
                <MetricCard
                  label="MTTR"
                  value={summary.find((s) => s.category === "web_application")?.mttrDays ? `${summary.find((s) => s.category === "web_application")!.mttrDays}d` : "-"}
                  icon={Clock}
                  color="text-primary"
                />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Trend */}
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Tendência Web Application</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {webTrend.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <AreaChart data={webTrend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <defs>
                            {(["critical", "high", "medium", "low"] as const).map((s) => (
                              <linearGradient key={s} id={`wg-${s}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor={SEV_COLORS[s]} stopOpacity={0.5} />
                                <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0.05} />
                              </linearGradient>
                            ))}
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="day" tick={{ fontSize: 10 }} tickFormatter={fmtDay} stroke="var(--muted-foreground)" />
                          <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip content={<SevTooltip />} />
                          {(["critical", "high", "medium", "low"] as const).map((s) => (
                            <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_COLORS[s]} fill={`url(#wg-${s})`} strokeWidth={1.5} dot={false} />
                          ))}
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Severity pie */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Distribuição</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {webSeverityPie.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie data={webSeverityPie} cx="50%" cy="50%" innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value">
                            {webSeverityPie.map((e, i) => (
                              <Cell key={i} fill={SEV_COLORS[e.name as keyof typeof SEV_COLORS] ?? "#888"} />
                            ))}
                          </Pie>
                          <Tooltip formatter={(v, n) => [v, SEV_PT[n as string] ?? n]} />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n) => SEV_PT[n] ?? n} />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Top findings by rule */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Top Achados por Categoria</CardTitle>
                </CardHeader>
                <CardContent>
                  {(webStats?.topFindings ?? []).length === 0 ? (
                    <Empty msg="Nenhum achado de Web Application no período" />
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Categoria / Regra</TableHead>
                          <TableHead className="text-right">Total</TableHead>
                          <TableHead className="text-right">Crítica/Alta</TableHead>
                          <TableHead className="text-right">Abertas</TableHead>
                          <TableHead>Severidade</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(webStats?.topFindings ?? []).map((f, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-medium text-sm max-w-[240px] truncate">{f.rule}</TableCell>
                            <TableCell className="text-right">{f.total}</TableCell>
                            <TableCell className="text-right">
                              {f.high_sev > 0 ? <span className="text-destructive font-medium">{f.high_sev}</span> : "0"}
                            </TableCell>
                            <TableCell className="text-right">{f.open_count}</TableCell>
                            <TableCell>
                              <Badge style={getSeverityStyle(f.top_severity)} className="text-xs">{SEV_PT[f.top_severity] ?? f.top_severity}</Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>

              {/* Journey history */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Execuções</CardTitle>
                </CardHeader>
                <CardContent>
                  <JourneyHistory history={histWeb} />
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: DESCOBERTA DE APIs                                       */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="api_discovery" className="space-y-6">

              {/* ── Métricas de inventário ── */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard label="APIs Mapeadas" value={inventoryTotals.total_apis} icon={Globe} color="text-primary" />
                <MetricCard label="Endpoints Totais" value={inventoryTotals.total_endpoints} icon={Activity} color="text-primary" />
                <MetricCard label="Sem Autenticação" value={inventoryTotals.unauth_endpoints} icon={XCircle} color={inventoryTotals.unauth_endpoints > 0 ? "text-orange-400" : "text-muted-foreground"} sub="endpoints expostos" />
                <MetricCard label="Novos no Período" value={recentDiscoveries.length} icon={Zap} color={recentDiscoveries.length > 0 ? "text-yellow-500" : "text-muted-foreground"} sub="endpoints descobertos" />
              </div>

              {/* ── Inventário de APIs + Métodos HTTP ── */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Inventário de APIs</CardTitle>
                    {inventoryApis.length > 0 && (
                      <p className="text-xs text-muted-foreground mt-0.5">Clique em uma linha para filtrar os achados de segurança</p>
                    )}
                  </CardHeader>
                  <CardContent className="p-0">
                    {inventoryApis.length === 0 ? (
                      <div className="px-6 py-8"><Empty msg="Nenhuma API mapeada. Execute uma jornada de Descoberta de APIs para começar." /></div>
                    ) : (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>API / Ativo</TableHead>
                            <TableHead className="text-right w-20">Endpoints</TableHead>
                            <TableHead className="text-right w-20">Auth</TableHead>
                            <TableHead className="text-right w-20">Sem Auth</TableHead>
                            <TableHead className="text-right w-20">Achados</TableHead>
                            <TableHead className="w-32">Métodos</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {inventoryApis.map((api) => (
                            <TableRow key={api.apiId} className={`cursor-pointer transition-colors ${selectedApiId === api.apiId ? "bg-primary/10 border-l-2 border-l-primary" : "hover:bg-muted/20"}`} onClick={() => setSelectedApiId(selectedApiId === api.apiId ? "all" : api.apiId)}>
                              <TableCell>
                                <div className="font-mono text-xs truncate max-w-[180px]" title={api.baseUrl}>{api.baseUrl}</div>
                                {api.assetName && <div className="text-xs text-muted-foreground">{api.assetName}</div>}
                              </TableCell>
                              <TableCell className="text-right font-semibold">{api.endpointCount}</TableCell>
                              <TableCell className="text-right">
                                {api.authCount > 0 ? <span className="text-green-500">{api.authCount}</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell className="text-right">
                                {api.unauthCount > 0 ? <span className="text-orange-400 font-semibold">{api.unauthCount}</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell className="text-right">
                                {api.highRiskCount > 0 ? <span className="text-destructive font-semibold">{api.highRiskCount}</span> : api.openFindingCount > 0 ? <span className="text-orange-400">{api.openFindingCount}</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell>
                                <div className="flex gap-0.5 flex-wrap">
                                  {(["GET","POST","PUT","PATCH","DELETE"] as const).map((m) => api.methods[m] > 0 && (
                                    <span key={m} className="text-[10px] font-mono px-1 py-0.5 rounded" style={{ backgroundColor: `${["GET","POST","PUT","PATCH","DELETE"].indexOf(m) < 5 ? ["#22c55e20","#3b82f620","#f59e0b20","#8b5cf620","#ef444420"][["GET","POST","PUT","PATCH","DELETE"].indexOf(m)] : "#88888820"}`, color: ["#22c55e","#3b82f6","#f59e0b","#8b5cf6","#ef4444"][["GET","POST","PUT","PATCH","DELETE"].indexOf(m)] }}>
                                      {m} {api.methods[m]}
                                    </span>
                                  ))}
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </CardContent>
                  {selectedApiId !== "all" && (
                    <div className="px-4 pb-3 flex items-center gap-2">
                      <span className="text-xs text-primary font-medium">Filtro ativo:</span>
                      <span className="text-xs font-mono text-muted-foreground">{inventoryApis.find(a => a.apiId === selectedApiId)?.baseUrl ?? selectedApiId}</span>
                      <button onClick={() => setSelectedApiId("all")} className="text-xs text-muted-foreground hover:text-foreground transition-colors ml-auto">✕ Limpar</button>
                    </div>
                  )}
                </Card>

                <div className="flex flex-col gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base">Métodos HTTP</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {methodTotalsData.length === 0 ? (
                        <Empty />
                      ) : (
                        <ResponsiveContainer width="100%" height={160}>
                          <BarChart data={methodTotalsData} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                            <XAxis type="number" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                            <YAxis dataKey="method" type="category" tick={{ fontSize: 11, fontFamily: "monospace" }} stroke="var(--muted-foreground)" width={52} />
                            <Tooltip formatter={(v) => [v, "endpoints"]} />
                            <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                              {methodTotalsData.map((entry) => (
                                <Cell key={entry.method} fill={{"GET":"#22c55e","POST":"#3b82f6","PUT":"#f59e0b","PATCH":"#8b5cf6","DELETE":"#ef4444","HEAD":"#64748b","OPTIONS":"#64748b"}[entry.method] ?? "#6b7280"} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      )}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base">Cobertura de Autenticação</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {authCoveragePie.length === 0 ? (
                        <Empty />
                      ) : (
                        <ResponsiveContainer width="100%" height={150}>
                          <PieChart>
                            <Pie data={authCoveragePie} cx="50%" cy="50%" innerRadius={36} outerRadius={58} paddingAngle={3} dataKey="value">
                              {authCoveragePie.map((e, i) => (
                                <Cell key={i} fill={AUTH_COLORS[e.name] ?? "#888"} />
                              ))}
                            </Pie>
                            <Tooltip formatter={(v, n) => [v, AUTH_PT[n as string] ?? n]} />
                            <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} formatter={(n) => AUTH_PT[n] ?? n} />
                          </PieChart>
                        </ResponsiveContainer>
                      )}
                    </CardContent>
                  </Card>
                </div>
              </div>

              {/* ── Fonte de Descoberta + Descobertas Recentes ── */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Fonte de Descoberta</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {(apiInventory?.sourceCounts ?? []).length === 0 ? (
                      <Empty msg="Nenhum dado de fonte disponível" />
                    ) : (
                      <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={apiInventory!.sourceCounts} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                          <XAxis type="number" tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <YAxis dataKey="source" type="category" tick={{ fontSize: 11 }} stroke="var(--muted-foreground)" width={70}
                            tickFormatter={(v) => sourceLabels[v] ?? v}
                          />
                          <Tooltip formatter={(v, _, props) => [v, sourceLabels[props.payload?.source] ?? props.payload?.source]} />
                          <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                            {(apiInventory?.sourceCounts ?? []).map((entry) => (
                              <Cell key={entry.source} fill={SOURCE_COLORS[entry.source] ?? "#6b7280"} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Descobertas Recentes — Últimos {period} dias</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    {recentDiscoveries.length === 0 ? (
                      <div className="px-6 py-8"><Empty msg="Nenhum endpoint descoberto no período" /></div>
                    ) : (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-20">Método</TableHead>
                            <TableHead>Caminho</TableHead>
                            <TableHead>API</TableHead>
                            <TableHead className="w-36">Descoberto em</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {recentDiscoveries.slice(0, 15).map((d, i) => (
                            <TableRow key={i}>
                              <TableCell>
                                <span className="text-xs font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor: `${{"GET":"#22c55e","POST":"#3b82f6","PUT":"#f59e0b","PATCH":"#8b5cf6","DELETE":"#ef4444"}[d.method] ?? "#6b7280"}20`, color: {"GET":"#22c55e","POST":"#3b82f6","PUT":"#f59e0b","PATCH":"#8b5cf6","DELETE":"#ef4444"}[d.method] ?? "#6b7280" }}>
                                  {d.method}
                                </span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{d.path}</TableCell>
                              <TableCell className="text-xs text-muted-foreground truncate max-w-[160px]" title={d.baseUrl}>{d.baseUrl}</TableCell>
                              <TableCell className="text-xs text-muted-foreground">{new Date(d.discoveredAt).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* ── Histórico de execuções ── */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Execuções</CardTitle>
                </CardHeader>
                <CardContent>
                  <JourneyHistory history={histApi} />
                </CardContent>
              </Card>
            </TabsContent>

            {/* ════════════════════════════════════════════════════════════ */}
            {/* TAB: SEGURANÇA DE APIs                                       */}
            {/* ════════════════════════════════════════════════════════════ */}
            <TabsContent value="api_security" className="space-y-6">

              {/* ── Filtro por API ── */}
              {inventoryApis.length > 0 && (
                <div className="flex items-center gap-3">
                  <span className="text-sm text-muted-foreground shrink-0">Filtrar por API:</span>
                  <Select value={selectedApiId} onValueChange={setSelectedApiId}>
                    <SelectTrigger className="w-64">
                      <SelectValue placeholder="Todas as APIs" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">Todas as APIs</SelectItem>
                      {inventoryApis.map((api) => (
                        <SelectItem key={api.apiId} value={api.apiId}>
                          <span className="font-mono text-xs">{api.baseUrl}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {selectedApiId !== "all" && (
                    <button onClick={() => setSelectedApiId("all")} className="text-xs text-muted-foreground hover:text-foreground transition-colors">
                      ✕ Limpar filtro
                    </button>
                  )}
                </div>
              )}

              {/* ── Métricas de achados ── */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <MetricCard label="Total de Achados" value={apiSummary.total} icon={Shield} color="text-muted-foreground" />
                <MetricCard label="Críticos" value={apiSummary.critical} icon={AlertTriangle} color={apiSummary.critical > 0 ? "text-destructive" : "text-muted-foreground"} />
                <MetricCard label="Abertos" value={apiSummary.open_count} icon={XCircle} color={apiSummary.open_count > 0 ? "text-orange-400" : "text-muted-foreground"} />
                <MetricCard label="Categorias OWASP" value={uniqueApiCategories} icon={Zap} color="text-primary" sub="categorias com achados" />
              </div>

              {/* ── OWASP API Top 10 ── */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">OWASP API Security Top 10 — 2023</CardTitle>
                </CardHeader>
                <CardContent>
                  {apiOwaspFiltered.length === 0 ? (
                    <Empty msg="Nenhum achado de segurança de API no período" />
                  ) : (
                    <div className="space-y-2">
                      {OWASP_API_KEYS.map((key) => {
                        const item = apiOwasp.find((x) => x.code === OWASP_API_CATEGORY_LABELS[key].codigo)!;
                        const info = OWASP_API_CATEGORY_LABELS[key];
                        const maxTotal = Math.max(1, ...apiOwasp.map((x) => x.total));
                        return (
                          <div key={key} className="flex items-center gap-3">
                            <div className="text-xs font-mono text-muted-foreground w-16 shrink-0">{info.codigo}</div>
                            <div className="flex-1 min-w-0">
                              <div className="text-xs text-muted-foreground truncate mb-0.5">{info.titulo}</div>
                              <div className="flex h-4 w-full rounded overflow-hidden bg-muted/30">
                                {item.critical > 0 && <div style={{ width: `${(item.critical / maxTotal) * 100}%`, backgroundColor: SEV_COLORS.critical }} title={`Crítico: ${item.critical}`} />}
                                {item.high > 0 && <div style={{ width: `${(item.high / maxTotal) * 100}%`, backgroundColor: SEV_COLORS.high }} title={`Alto: ${item.high}`} />}
                                {item.medium > 0 && <div style={{ width: `${(item.medium / maxTotal) * 100}%`, backgroundColor: SEV_COLORS.medium }} title={`Médio: ${item.medium}`} />}
                                {item.low > 0 && <div style={{ width: `${(item.low / maxTotal) * 100}%`, backgroundColor: SEV_COLORS.low }} title={`Baixo: ${item.low}`} />}
                              </div>
                            </div>
                            <div className="text-xs font-semibold w-8 text-right shrink-0">
                              {item.total > 0 ? <span className="text-foreground">{item.total}</span> : <span className="text-muted-foreground">—</span>}
                            </div>
                          </div>
                        );
                      })}
                      <div className="flex gap-4 pt-2 text-xs text-muted-foreground">
                        {(["critical", "high", "medium", "low"] as const).map((s) => (
                          <span key={s} className="flex items-center gap-1">
                            <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: SEV_COLORS[s] }} />
                            {SEV_PT[s]}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* ── Tendência + Donut de severidade ── */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Tendência de Achados</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {(apiStats?.trend ?? []).length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <AreaChart data={apiStats!.trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                          <defs>
                            {(["critical", "high", "medium", "low"] as const).map((s) => (
                              <linearGradient key={s} id={`ag-${s}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor={SEV_COLORS[s]} stopOpacity={0.5} />
                                <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0.05} />
                              </linearGradient>
                            ))}
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                          <XAxis dataKey="day" tick={{ fontSize: 10 }} tickFormatter={fmtDay} stroke="var(--muted-foreground)" />
                          <YAxis tick={{ fontSize: 10 }} stroke="var(--muted-foreground)" />
                          <Tooltip content={<SevTooltip />} />
                          {(["critical", "high", "medium", "low"] as const).map((s) => (
                            <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={SEV_COLORS[s]} fill={`url(#ag-${s})`} strokeWidth={1.5} dot={false} />
                          ))}
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Distribuição por Severidade</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {apiSevPie.length === 0 ? (
                      <Empty />
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie data={apiSevPie} cx="50%" cy="50%" innerRadius={42} outerRadius={68} paddingAngle={3} dataKey="value">
                            {apiSevPie.map((e, i) => (
                              <Cell key={i} fill={SEV_COLORS[e.name as keyof typeof SEV_COLORS] ?? "#888"} />
                            ))}
                          </Pie>
                          <Tooltip formatter={(v, n) => [v, SEV_PT[n as string] ?? n]} />
                          <Legend iconSize={8} wrapperStyle={{ fontSize: 11 }} formatter={(n) => SEV_PT[n] ?? n} />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* ── Mapa de calor OWASP × Severidade ── */}
              {apiOwaspFiltered.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Mapa de Calor — OWASP API × Severidade</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <HeatMap
                      rowLabels={apiOwaspFiltered.map((x) => x.code)}
                      colLabels={["critical", "high", "medium", "low"]}
                      data={Object.fromEntries(
                        apiOwaspFiltered.map((x) => [x.code, { critical: x.critical, high: x.high, medium: x.medium, low: x.low }]),
                      )}
                      getColor={(col, intensity) => {
                        const base = SEV_COLORS[col as keyof typeof SEV_COLORS] ?? "#888";
                        if (intensity === 0) return "transparent";
                        const hex = base.replace("#", "");
                        const r = parseInt(hex.slice(0, 2), 16);
                        const g = parseInt(hex.slice(2, 4), 16);
                        const b = parseInt(hex.slice(4, 6), 16);
                        return `rgba(${r},${g},${b},${0.15 + intensity * 0.85})`;
                      }}
                    />
                  </CardContent>
                </Card>
              )}

              {/* ── Histórico de execuções ── */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Histórico de Execuções</CardTitle>
                </CardHeader>
                <CardContent>
                  <JourneyHistory history={histApi} />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}
