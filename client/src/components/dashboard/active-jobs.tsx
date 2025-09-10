import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Search, Users, Worm } from "lucide-react";
import { Job } from "@shared/schema";

export default function ActiveJobs() {
  const { data: runningJobs = [], isLoading } = useQuery<Job[]>({
    queryKey: ["/api/dashboard/running-jobs"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  const getJobIcon = (journeyType?: string) => {
    switch (journeyType) {
      case 'attack_surface':
        return Search;
      case 'ad_hygiene':
        return Users;
      case 'edr_av':
        return Worm;
      default:
        return Search;
    }
  };

  const getJobIconBg = (journeyType?: string) => {
    switch (journeyType) {
      case 'attack_surface':
        return 'bg-primary/20';
      case 'ad_hygiene':
        return 'bg-accent/20';
      case 'edr_av':
        return 'bg-chart-5/20';
      default:
        return 'bg-primary/20';
    }
  };

  const getJobIconColor = (journeyType?: string) => {
    switch (journeyType) {
      case 'attack_surface':
        return 'text-primary';
      case 'ad_hygiene':
        return 'text-accent';
      case 'edr_av':
        return 'text-chart-5';
      default:
        return 'text-primary';
    }
  };

  if (isLoading) {
    return (
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle>Jobs em Execução</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="h-16 bg-muted rounded-lg"></div>
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
            Jobs em Execução
          </CardTitle>
          <Badge variant="secondary" data-testid="running-jobs-count">
            {runningJobs.length} Ativos
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="p-6">
        {runningJobs.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-muted-foreground">Nenhum job em execução no momento</p>
          </div>
        ) : (
          <div className="space-y-4">
            {runningJobs.map((job) => {
              const Icon = getJobIcon();
              const iconBg = getJobIconBg();
              const iconColor = getJobIconColor();
              
              return (
                <div 
                  key={job.id} 
                  className="job-running flex items-center justify-between p-4 bg-muted/50 rounded-lg border border-border"
                  data-testid={`job-${job.id}`}
                >
                  <div className="flex items-center space-x-3">
                    <div className={`w-10 h-10 ${iconBg} rounded-lg flex items-center justify-center`}>
                      <Icon className={iconColor} />
                    </div>
                    <div>
                      <p className="font-medium text-foreground">
                        {job.currentTask || 'Executando jornada'}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        <span>{job.progress || 0}%</span> completo
                        {job.currentTask && (
                          <>
                            {' • '}
                            <span>{job.currentTask}</span>
                          </>
                        )}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className={`w-2 h-2 ${iconColor.replace('text-', 'bg-')} rounded-full pulse-animation`}></div>
                    <span className="text-sm text-muted-foreground">
                      {job.startedAt 
                        ? `${Math.floor((Date.now() - new Date(job.startedAt).getTime()) / 60000)}m`
                        : '0m'
                      }
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
