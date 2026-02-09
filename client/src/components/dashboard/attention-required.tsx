import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, XCircle, Clock, ArrowRight } from "lucide-react";
import { Link } from "wouter";
import { Threat } from "@shared/schema";

interface Job {
  id: string;
  status: string;
  error?: string;
  journeyId: string;
  createdAt: string;
}

interface AlertItem {
  id: string;
  icon: React.ComponentType<{ className?: string }>;
  iconClass: string;
  title: string;
  description: string;
  href: string;
  priority: number;
}

export default function AttentionRequired() {
  const { data: threats = [] } = useQuery<Threat[]>({
    queryKey: ["/api/dashboard/recent-threats"],
    refetchInterval: 30000,
  });

  const { data: jobs = [] } = useQuery<Job[]>({
    queryKey: ["/api/jobs"],
    refetchInterval: 10000,
    select: (data: any) => Array.isArray(data) ? data : [],
  });

  const alerts: AlertItem[] = [];

  // Critical open threats
  const criticalThreats = threats.filter(
    (t) => t.severity === "critical" && t.status === "open"
  );
  if (criticalThreats.length > 0) {
    alerts.push({
      id: "critical-threats",
      icon: AlertTriangle,
      iconClass: "text-destructive",
      title: `${criticalThreats.length} ameaça${criticalThreats.length > 1 ? "s" : ""} crítica${criticalThreats.length > 1 ? "s" : ""} aberta${criticalThreats.length > 1 ? "s" : ""}`,
      description: "Requerem análise e tratamento imediato",
      href: "/threats?severity=critical&status=open",
      priority: 0,
    });
  }

  // High severity open threats
  const highThreats = threats.filter(
    (t) => t.severity === "high" && t.status === "open"
  );
  if (highThreats.length > 0) {
    alerts.push({
      id: "high-threats",
      icon: AlertTriangle,
      iconClass: "text-orange-500",
      title: `${highThreats.length} ameaça${highThreats.length > 1 ? "s" : ""} de alta severidade`,
      description: "Abertas e aguardando investigação",
      href: "/threats?severity=high&status=open",
      priority: 1,
    });
  }

  // Failed jobs in last 24h
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recentFailedJobs = jobs.filter(
    (j) =>
      (j.status === "failed" || j.status === "timeout") &&
      new Date(j.createdAt).getTime() > oneDayAgo
  );
  if (recentFailedJobs.length > 0) {
    alerts.push({
      id: "failed-jobs",
      icon: XCircle,
      iconClass: "text-destructive",
      title: `${recentFailedJobs.length} job${recentFailedJobs.length > 1 ? "s" : ""} falhou nas últimas 24h`,
      description: "Verifique os logs para identificar o problema",
      href: "/jobs",
      priority: 2,
    });
  }

  // Stale jobs (running for more than 2 hours)
  const twoHoursAgo = Date.now() - 2 * 60 * 60 * 1000;
  const staleJobs = jobs.filter(
    (j) =>
      j.status === "running" &&
      new Date(j.createdAt).getTime() < twoHoursAgo
  );
  if (staleJobs.length > 0) {
    alerts.push({
      id: "stale-jobs",
      icon: Clock,
      iconClass: "text-yellow-500",
      title: `${staleJobs.length} job${staleJobs.length > 1 ? "s" : ""} em execução há mais de 2h`,
      description: "Podem estar travados e necessitar cancelamento",
      href: "/jobs",
      priority: 3,
    });
  }

  // Sort by priority
  alerts.sort((a, b) => a.priority - b.priority);

  // Don't render if no alerts
  if (alerts.length === 0) {
    return null;
  }

  return (
    <Card className="bg-card border-border border-l-4 border-l-destructive">
      <CardHeader className="pb-3">
        <CardTitle className="text-lg font-semibold text-foreground flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-destructive" />
          Requer Atenção
          <span className="ml-auto text-xs font-normal text-muted-foreground bg-destructive/10 text-destructive px-2 py-1 rounded-full">
            {alerts.length} {alerts.length === 1 ? "alerta" : "alertas"}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-2">
          {alerts.map((alert) => (
            <Link key={alert.id} href={alert.href}>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/60 transition-colors cursor-pointer group">
                <alert.icon className={`h-5 w-5 ${alert.iconClass} flex-shrink-0`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">
                    {alert.title}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {alert.description}
                  </p>
                </div>
                <ArrowRight className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors flex-shrink-0" />
              </div>
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
