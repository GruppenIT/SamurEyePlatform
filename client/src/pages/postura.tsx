import { useQuery } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import AttentionRequired from "@/components/dashboard/attention-required";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Link } from "wouter";
import {
  ShieldCheck,
  AlertTriangle,
  Server,
  Activity,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  ExternalLink,
} from "lucide-react";
import { Threat, Host, Job } from "@shared/schema";

interface PostureScore {
  score: number;
  totalHosts: number;
  hostsAtRisk: number;
  history: { day: string; score: number }[];
}

interface CategoryStats {
  [category: string]: {
    open: number;
    total: number;
    critical: number;
    high: number;
  };
}

interface ActivityItem {
  type: "threat" | "job";
  id: string;
  title?: string;
  severity?: string;
  status: string;
  task?: string;
  journeyId?: string;
  timestamp: string;
}

const categoryLabels: Record<string, string> = {
  attack_surface: "Attack Surface",
  ad_security: "AD Security",
  edr_av: "EDR/AV",
  web_application: "Web Application",
  uncategorized: "Outros",
};

export default function Postura() {
  const { connected } = useWebSocket();

  const { data: posture } = useQuery<PostureScore>({
    queryKey: ["/api/posture/score"],
    refetchInterval: 60000,
  });

  const { data: categoryStats } = useQuery<CategoryStats>({
    queryKey: ["/api/threats/stats-by-category"],
    refetchInterval: 60000,
  });

  const { data: activityFeed = [] } = useQuery<ActivityItem[]>({
    queryKey: ["/api/activity/feed?limit=10"],
    refetchInterval: 30000,
  });

  const { data: threats = [] } = useQuery<Threat[]>({
    queryKey: ["/api/dashboard/recent-threats"],
    refetchInterval: 30000,
  });

  const { data: hosts = [] } = useQuery<Host[]>({
    queryKey: ["/api/hosts"],
    refetchInterval: 60000,
    select: (data: any) => (Array.isArray(data) ? data : []),
  });

  const { data: jobs = [] } = useQuery<Job[]>({
    queryKey: ["/api/jobs"],
    refetchInterval: 10000,
    select: (data: any) => (Array.isArray(data) ? data : []),
  });

  // Computed metrics
  const newThreats24h = threats.filter(
    (t) => new Date(t.createdAt).getTime() > Date.now() - 24 * 60 * 60 * 1000
  ).length;

  const openThreats = threats.filter((t) => t.status === "open").length;

  const criticalHosts = hosts.filter(
    (h) => (h.riskScore || 0) >= 90
  ).length;

  const runningJobs = jobs.filter((j) => j.status === "running").length;
  const failedJobs24h = jobs.filter(
    (j) =>
      (j.status === "failed" || j.status === "timeout") &&
      new Date(j.createdAt).getTime() > Date.now() - 24 * 60 * 60 * 1000
  ).length;

  // Top 5 hosts by risk
  const topHosts = [...hosts]
    .filter((h) => (h.riskScore || 0) > 0)
    .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
    .slice(0, 5);

  // Score color
  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-400";
    if (score >= 60) return "text-yellow-400";
    if (score >= 40) return "text-orange-400";
    return "text-red-400";
  };

  const getScoreProgressColor = (score: number) => {
    if (score >= 80) return "bg-green-500";
    if (score >= 60) return "bg-yellow-500";
    if (score >= 40) return "bg-orange-500";
    return "bg-red-500";
  };

  const getRiskBadgeStyle = (score: number): React.CSSProperties => {
    if (score >= 90) return { backgroundColor: "var(--severity-critical)", color: "#fff" };
    if (score >= 70) return { backgroundColor: "var(--severity-high)", color: "#fff" };
    if (score >= 40) return { backgroundColor: "var(--severity-medium)", color: "var(--background)" };
    return { backgroundColor: "var(--severity-low)", color: "#fff" };
  };

  const formatTimeAgo = (date: string) => {
    const diff = Date.now() - new Date(date).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h`;
    return `${Math.floor(hours / 24)}d`;
  };

  const score = posture?.score ?? 0;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar
          title="Postura de Seguranca"
          subtitle="Visao consolidada da exposicao e riscos"
          wsConnected={connected}
        />
        <div className="p-6 space-y-6 overflow-auto h-[calc(100%-4rem)]">
          {/* Alerts */}
          <AttentionRequired />

          {/* Score Bar */}
          <Card>
            <CardContent className="py-5 px-6">
              <div className="flex items-center gap-6">
                <div className="flex items-center gap-3">
                  <ShieldCheck className={`h-8 w-8 ${getScoreColor(score)}`} />
                  <div>
                    <div className="flex items-baseline gap-2">
                      <span className={`text-3xl font-bold ${getScoreColor(score)}`}>
                        {score}
                      </span>
                      <span className="text-sm text-muted-foreground">/100</span>
                    </div>
                    <p className="text-xs text-muted-foreground">Postura Global</p>
                  </div>
                </div>
                <div className="flex-1">
                  <div className="h-3 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${getScoreProgressColor(score)}`}
                      style={{ width: `${score}%` }}
                    />
                  </div>
                </div>
                <div className="text-right text-sm text-muted-foreground">
                  <p>{posture?.totalHosts || 0} hosts monitorados</p>
                  <p>{posture?.hostsAtRisk || 0} em risco</p>
                </div>
              </div>
              {/* Sparkline */}
              {posture?.history && posture.history.length > 1 && (
                <div className="mt-3 flex items-end gap-[2px] h-8">
                  {posture.history.slice(-30).map((h, i) => (
                    <div
                      key={i}
                      className={`flex-1 rounded-sm ${getScoreProgressColor(h.score)} opacity-60`}
                      style={{ height: `${Math.max(4, h.score * 0.32)}px` }}
                      title={`${h.day}: ${h.score}/100`}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Delta Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <DeltaCard
              label="Novas Ameacas (24h)"
              value={newThreats24h}
              icon={AlertTriangle}
              color={newThreats24h > 0 ? "text-destructive" : "text-muted-foreground"}
            />
            <DeltaCard
              label="Abertas Total"
              value={openThreats}
              icon={Activity}
              color={openThreats > 10 ? "text-orange-400" : "text-muted-foreground"}
            />
            <DeltaCard
              label="Hosts Risco Critico"
              value={criticalHosts}
              icon={Server}
              color={criticalHosts > 0 ? "text-destructive" : "text-muted-foreground"}
            />
            <DeltaCard
              label="Jobs"
              value={runningJobs}
              suffix={failedJobs24h > 0 ? `/ ${failedJobs24h} falhos` : "ativos"}
              icon={Activity}
              color={failedJobs24h > 0 ? "text-orange-400" : "text-primary"}
            />
          </div>

          {/* Two columns: Top Hosts + Category Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top 5 Hosts */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Top Hosts por Risco</CardTitle>
              </CardHeader>
              <CardContent>
                {topHosts.length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    Nenhum host com risco identificado
                  </p>
                ) : (
                  <div className="space-y-2">
                    {topHosts.map((host) => (
                      <Link key={host.id} href="/hosts">
                        <div className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 cursor-pointer group">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate">{host.name}</p>
                            {host.ips && host.ips.length > 0 && (
                              <p className="text-xs text-muted-foreground">{host.ips[0]}</p>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge style={getRiskBadgeStyle(host.riskScore || 0)}>
                              {host.riskScore || 0}
                            </Badge>
                            <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100" />
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Category Distribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Ameacas por Tipo de Jornada</CardTitle>
              </CardHeader>
              <CardContent>
                {!categoryStats || Object.keys(categoryStats).length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">
                    Nenhuma ameaca registrada
                  </p>
                ) : (
                  <div className="space-y-3">
                    {Object.entries(categoryStats)
                      .filter(([_, s]) => s.total > 0)
                      .sort((a, b) => b[1].open - a[1].open)
                      .map(([cat, stats]) => (
                        <div key={cat} className="space-y-1">
                          <div className="flex items-center justify-between text-sm">
                            <span className="font-medium">{categoryLabels[cat] || cat}</span>
                            <span className="text-muted-foreground">
                              {stats.open} abertas / {stats.total} total
                            </span>
                          </div>
                          <div className="flex gap-1 h-2">
                            {stats.critical > 0 && (
                              <div
                                className="rounded-sm"
                                style={{
                                  backgroundColor: "var(--severity-critical)",
                                  width: `${(stats.critical / stats.total) * 100}%`,
                                }}
                                title={`${stats.critical} criticas`}
                              />
                            )}
                            {stats.high > 0 && (
                              <div
                                className="rounded-sm"
                                style={{
                                  backgroundColor: "var(--severity-high)",
                                  width: `${(stats.high / stats.total) * 100}%`,
                                }}
                                title={`${stats.high} altas`}
                              />
                            )}
                            {stats.total - stats.critical - stats.high > 0 && (
                              <div
                                className="rounded-sm bg-muted"
                                style={{
                                  width: `${((stats.total - stats.critical - stats.high) / stats.total) * 100}%`,
                                }}
                              />
                            )}
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Activity Feed */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Atividade Recente</CardTitle>
            </CardHeader>
            <CardContent>
              {activityFeed.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  Nenhuma atividade recente
                </p>
              ) : (
                <div className="space-y-1">
                  {activityFeed.map((item, i) => (
                    <div
                      key={`${item.type}-${item.id}-${i}`}
                      className="flex items-center gap-3 py-2 px-2 rounded-md hover:bg-muted/30"
                    >
                      <span className="text-xs text-muted-foreground w-8 shrink-0">
                        {formatTimeAgo(item.timestamp)}
                      </span>
                      {item.type === "threat" ? (
                        <>
                          <div
                            className="w-2 h-2 rounded-full shrink-0"
                            style={{
                              backgroundColor:
                                item.severity === "critical"
                                  ? "var(--severity-critical)"
                                  : item.severity === "high"
                                  ? "var(--severity-high)"
                                  : "var(--severity-medium)",
                            }}
                          />
                          <span className="text-sm truncate flex-1">{item.title}</span>
                          <Badge variant="outline" className="text-xs shrink-0">
                            {item.severity}
                          </Badge>
                        </>
                      ) : (
                        <>
                          <div
                            className="w-2 h-2 rounded-full shrink-0"
                            style={{
                              backgroundColor:
                                item.status === "completed"
                                  ? "var(--status-closed)"
                                  : item.status === "failed"
                                  ? "var(--severity-critical)"
                                  : "var(--severity-medium)",
                            }}
                          />
                          <span className="text-sm truncate flex-1">
                            Job {item.id.slice(0, 8)} - {item.status === 'completed' ? 'concluido' : item.status === 'failed' ? 'falhou' : item.status}
                          </span>
                          <Badge variant="outline" className="text-xs shrink-0">
                            job
                          </Badge>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}

function DeltaCard({
  label,
  value,
  suffix,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  suffix?: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
}) {
  return (
    <Card>
      <CardContent className="py-4 px-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <div className="flex items-baseline gap-1 mt-1">
              <span className={`text-2xl font-bold ${color}`}>{value}</span>
              {suffix && (
                <span className="text-xs text-muted-foreground">{suffix}</span>
              )}
            </div>
          </div>
          <Icon className={`h-5 w-5 ${color} opacity-50`} />
        </div>
      </CardContent>
    </Card>
  );
}
