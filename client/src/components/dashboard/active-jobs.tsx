import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Search, Users, Worm, X, AlertCircle, Cpu } from "lucide-react";
import { Job } from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export default function ActiveJobs() {
  const { toast } = useToast();
  
  const { data: runningJobs = [], isLoading } = useQuery<Job[]>({
    queryKey: ["/api/dashboard/running-jobs"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Função para cancelar job
  const handleCancelJob = async (jobId: string) => {
    try {
      await apiRequest(`/api/jobs/${jobId}/cancel-process`, 'POST');
      
      toast({
        title: "Job cancelado",
        description: "O job foi marcado para cancelamento e os processos serão interrompidos.",
      });
      
      // Atualizar lista
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/running-jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
    } catch (error) {
      console.error('Erro ao cancelar job:', error);
      toast({
        title: "Erro ao cancelar",
        description: "Não foi possível cancelar o job. Tente novamente.",
        variant: "destructive",
      });
    }
  };

  // Função para extrair informações de PID do currentTask
  const extractPidInfo = (currentTask?: string) => {
    if (!currentTask) return null;
    
    const pidMatch = currentTask.match(/\((nmap|nuclei) pid (\d+)\)/);
    if (pidMatch) {
      return {
        processName: pidMatch[1] as 'nmap' | 'nuclei',
        pid: parseInt(pidMatch[2]),
        stage: currentTask.replace(pidMatch[0], '').trim()
      };
    }
    
    return null;
  };

  const getJobIcon = (journeyType?: string) => {
    switch (journeyType) {
      case 'attack_surface':
        return Search;
      case 'ad_security':
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
      case 'ad_security':
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
      case 'ad_security':
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
              const pidInfo = extractPidInfo(job.currentTask || undefined);
              
              return (
                <div 
                  key={job.id} 
                  className="job-running p-4 bg-muted/50 rounded-lg border border-border"
                  data-testid={`job-${job.id}`}
                >
                  {/* Header com ação e botão cancelar */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`w-10 h-10 ${iconBg} rounded-lg flex items-center justify-center`}>
                        <Icon className={iconColor} />
                      </div>
                      <div>
                        <p className="font-medium text-foreground">
                          {pidInfo?.stage || job.currentTask || 'Executando jornada'}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          <span>{job.progress || 0}%</span> completo
                        </p>
                      </div>
                    </div>
                    
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleCancelJob(job.id)}
                      className="h-8 px-3 text-destructive hover:text-destructive-foreground hover:bg-destructive"
                      data-testid={`button-cancel-${job.id}`}
                    >
                      <X className="h-3 w-3 mr-1" />
                      Cancelar
                    </Button>
                  </div>
                  
                  {/* Info detalhada com PID se disponível */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {pidInfo && (
                        <div className="flex items-center space-x-2 text-sm text-muted-foreground bg-background/50 px-2 py-1 rounded">
                          <Cpu className="h-3 w-3" />
                          <span className="font-mono">{pidInfo.processName}</span>
                          <Badge variant="secondary" className="text-xs px-1.5 py-0">
                            PID {pidInfo.pid}
                          </Badge>
                        </div>
                      )}
                      
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
                    
                    <div className="text-xs text-muted-foreground font-mono">
                      ID: {job.id.substring(0, 8)}
                    </div>
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
