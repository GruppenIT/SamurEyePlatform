import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useQuery } from "@tanstack/react-query";

export default function SystemHealth() {
  const { data: systemMetrics, isLoading } = useQuery({
    queryKey: ["/api/system/metrics"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  if (isLoading || !systemMetrics) {
    return (
      <Card className="bg-card border-border">
        <CardHeader className="border-b border-border">
          <CardTitle className="text-lg font-semibold text-foreground">
            Saúde do Sistema
          </CardTitle>
          <p className="text-sm text-muted-foreground">Carregando métricas...</p>
        </CardHeader>
        <CardContent className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-3/4"></div>
            <div className="h-4 bg-muted rounded w-1/2"></div>
            <div className="h-4 bg-muted rounded w-2/3"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-card border-border">
      <CardHeader className="border-b border-border">
        <CardTitle className="text-lg font-semibold text-foreground">
          Saúde do Sistema
        </CardTitle>
        <p className="text-sm text-muted-foreground">Status dos componentes</p>
      </CardHeader>
      <CardContent className="p-6">
        <div className="space-y-4">
          {/* Services Status */}
          {systemMetrics.services.map((service, index) => (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className={`status-indicator ${service.color}`}></span>
                <span className="text-sm font-medium text-foreground">
                  {service.name}
                </span>
              </div>
              <span className="text-xs text-muted-foreground">
                {service.status}
              </span>
            </div>
          ))}
          
          {/* CPU Usage */}
          <div className="mt-6 pt-4 border-t border-border">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-muted-foreground">Uso de CPU</span>
              <span className="font-medium text-foreground" data-testid="cpu-usage">
                {systemMetrics.cpu}%
              </span>
            </div>
            <Progress value={systemMetrics.cpu} className="h-2" />
          </div>
          
          {/* Memory Usage */}
          <div className="mt-4">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-muted-foreground">Uso de Memória</span>
              <span className="font-medium text-foreground" data-testid="memory-usage">
                {systemMetrics.memory}%
              </span>
            </div>
            <Progress value={systemMetrics.memory} className="h-2" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
