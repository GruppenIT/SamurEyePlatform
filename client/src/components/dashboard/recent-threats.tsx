import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "lucide-react";
import { Link } from "wouter";
import { Threat } from "@shared/schema";

export default function RecentThreats() {
  const { data: threats = [], isLoading } = useQuery<Threat[]>({
    queryKey: ["/api/dashboard/recent-threats"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const getSeverityStyle = (severity: string): React.CSSProperties => {
    const map: Record<string, { bg: string; color: string }> = {
      critical: { bg: 'var(--severity-critical)', color: '#fff' },
      high: { bg: 'var(--severity-high)', color: '#fff' },
      medium: { bg: 'var(--severity-medium)', color: 'var(--background)' },
      low: { bg: 'var(--severity-low)', color: '#fff' },
    };
    const s = map[severity] || { bg: 'var(--muted)', color: 'var(--muted-foreground)' };
    return { backgroundColor: s.bg, color: s.color };
  };

  const getSeverityLabel = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'CRÍTICA';
      case 'high':
        return 'ALTA';
      case 'medium':
        return 'MÉDIA';
      case 'low':
        return 'BAIXA';
      default:
        return severity.toUpperCase();
    }
  };

  const getThreatBorderClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'threat-critical';
      case 'high':
        return 'threat-high';
      case 'medium':
        return 'threat-medium';
      case 'low':
        return 'threat-low';
      default:
        return '';
    }
  };

  const formatTimeAgo = (date: string | Date) => {
    const now = new Date();
    const threatDate = typeof date === 'string' ? new Date(date) : date;
    const diffInMinutes = Math.floor((now.getTime() - threatDate.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 60) {
      return `${diffInMinutes}m atrás`;
    } else if (diffInMinutes < 24 * 60) {
      return `${Math.floor(diffInMinutes / 60)}h atrás`;
    } else {
      return `${Math.floor(diffInMinutes / (24 * 60))}d atrás`;
    }
  };

  if (isLoading) {
    return (
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle>Ameaças Recentes</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="h-20 bg-muted rounded-lg"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="bg-card border-border">
      <CardHeader className="border-b border-border">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold text-foreground">
            Ameaças Recentes
          </CardTitle>
          <Link href="/threats">
            <a className="text-primary hover:text-primary/80 text-sm font-medium" data-testid="link-view-all-threats">
              Ver todas
            </a>
          </Link>
        </div>
      </CardHeader>
      <CardContent className="p-6">
        {threats.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-muted-foreground">Nenhuma ameaça recente encontrada</p>
          </div>
        ) : (
          <div className="space-y-4">
            {threats.slice(0, 5).map((threat) => (
              <div 
                key={threat.id} 
                className={`p-4 bg-muted/30 rounded-lg ${getThreatBorderClass(threat.severity)}`}
                data-testid={`threat-${threat.id}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <Badge style={getSeverityStyle(threat.severity)}>
                        {getSeverityLabel(threat.severity)}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {formatTimeAgo(threat.createdAt)}
                      </span>
                    </div>
                    <h4 className="font-medium text-foreground mt-2">
                      {threat.title}
                    </h4>
                    {threat.evidence && typeof threat.evidence === 'object' && 'hostname' in threat.evidence && (
                      <p className="text-sm text-muted-foreground mt-1">
                        {threat.evidence.hostname as string}
                      </p>
                    )}
                    {threat.description && (
                      <p className="text-sm text-muted-foreground mt-1">
                        {threat.description}
                      </p>
                    )}
                  </div>
                  <Link href="/threats">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-muted-foreground hover:text-foreground ml-4"
                      data-testid={`button-view-threat-${threat.id}`}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
