import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Server, AlertTriangle, CheckCircle, Shield } from "lucide-react";
import { DashboardMetrics } from "@/types";

export default function MetricsOverview() {
  const { data: metrics, isLoading } = useQuery<DashboardMetrics>({
    queryKey: ["/api/dashboard/metrics"],
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <Card key={i} className="metric-card animate-pulse">
            <CardContent className="p-6">
              <div className="h-20 bg-muted rounded"></div>
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  const metricCards = [
    {
      title: "Ativos Ativos",
      value: metrics?.activeAssets || 0,
      icon: Server,
      iconBg: "bg-primary/20",
      iconColor: "text-primary",
      change: "+12%",
      changeText: "vs. mês anterior",
      changeColor: "text-chart-4",
    },
    {
      title: "Ameaças Críticas",
      value: metrics?.criticalThreats || 0,
      icon: AlertTriangle,
      iconBg: "bg-destructive/20",
      iconColor: "text-destructive",
      change: `+${metrics?.criticalThreats || 0}`,
      changeText: "novas nas últimas 24h",
      changeColor: "text-destructive",
    },
    {
      title: "Jobs Executados",
      value: metrics?.jobsExecuted || 0,
      icon: CheckCircle,
      iconBg: "bg-accent/20",
      iconColor: "text-accent",
      change: "98.2%",
      changeText: "taxa de sucesso",
      changeColor: "text-chart-4",
    },
    {
      title: "Cobertura",
      value: `${metrics?.coverage || 0}%`,
      icon: Shield,
      iconBg: "bg-chart-4/20",
      iconColor: "text-chart-4",
      change: "+2.1%",
      changeText: "dos ativos monitorados",
      changeColor: "text-chart-4",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {metricCards.map((metric, index) => (
        <Card key={index} className="metric-card">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">
                  {metric.title}
                </p>
                <p 
                  className={`text-3xl font-bold ${
                    metric.title === "Ameaças Críticas" ? "text-destructive" : "text-foreground"
                  }`}
                  data-testid={`metric-${metric.title.toLowerCase().replace(/\s+/g, '-')}`}
                >
                  {metric.value}
                </p>
              </div>
              <div className={`w-12 h-12 ${metric.iconBg} rounded-lg flex items-center justify-center`}>
                <metric.icon className={`${metric.iconColor} text-xl h-6 w-6`} />
              </div>
            </div>
            <div className="mt-4 flex items-center text-sm">
              <span className={`${metric.changeColor} mr-1`}>
                {metric.change}
              </span>
              <span className="text-muted-foreground">{metric.changeText}</span>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
