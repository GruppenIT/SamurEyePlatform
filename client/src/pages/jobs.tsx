import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import { useToast } from "@/hooks/use-toast";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Search, Eye, RefreshCw, Clock, CheckCircle, XCircle, AlertCircle } from "lucide-react";
import { Job, JobResult } from "@shared/schema";
import { JobUpdate } from "@/types";

export default function Jobs() {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);
  const [jobResult, setJobResult] = useState<JobResult | null>(null);
  
  const { toast } = useToast();
  const { lastMessage } = useWebSocket();

  const { data: jobs = [], isLoading, refetch } = useQuery<Job[]>({
    queryKey: ["/api/jobs"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  const { data: result, isLoading: isLoadingResult } = useQuery<JobResult>({
    queryKey: [`/api/jobs/${selectedJob?.id}/result`],
    enabled: !!selectedJob,
    retry: false,
  });

  // Handle WebSocket job updates
  useEffect(() => {
    if (lastMessage && lastMessage.type === 'jobUpdate') {
      const update = lastMessage.data as JobUpdate;
      toast({
        title: "Atualização de Job",
        description: `Job ${update.status === 'completed' ? 'concluído' : 'atualizado'}: ${update.progress || 0}%`,
      });
      refetch(); // Refresh job list
    }
  }, [lastMessage, toast, refetch]);

  useEffect(() => {
    if (result) {
      setJobResult(result);
    }
  }, [result]);

  const filteredJobs = jobs.filter(job => {
    const matchesSearch = job.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (job.currentTask && job.currentTask.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesStatus = statusFilter === "all" || job.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending':
        return Clock;
      case 'running':
        return RefreshCw;
      case 'completed':
        return CheckCircle;
      case 'failed':
        return XCircle;
      case 'timeout':
        return AlertCircle;
      default:
        return Clock;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return 'bg-muted text-muted-foreground';
      case 'running':
        return 'bg-primary/20 text-primary';
      case 'completed':
        return 'bg-chart-4/20 text-chart-4';
      case 'failed':
        return 'bg-destructive/20 text-destructive';
      case 'timeout':
        return 'bg-accent/20 text-accent';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'pending':
        return 'Pendente';
      case 'running':
        return 'Executando';
      case 'completed':
        return 'Concluído';
      case 'failed':
        return 'Falhou';
      case 'timeout':
        return 'Timeout';
      default:
        return status.charAt(0).toUpperCase() + status.slice(1);
    }
  };

  const formatDuration = (start?: string, end?: string) => {
    if (!start) return '-';
    
    const startTime = new Date(start);
    const endTime = end ? new Date(end) : new Date();
    const duration = Math.floor((endTime.getTime() - startTime.getTime()) / 1000);
    
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    
    return `${minutes}m ${seconds}s`;
  };

  const handleViewJob = async (job: Job) => {
    setSelectedJob(job);
    setJobResult(null);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Monitoramento de Jobs"
          subtitle="Acompanhe execuções e resultados das jornadas"
          actions={
            <Button
              onClick={() => refetch()}
              disabled={isLoading}
              data-testid="button-refresh-jobs"
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Atualizar
            </Button>
          }
        />
        
        <div className="p-6 space-y-6">
          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar jobs por ID ou tarefa..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-jobs"
                  />
                </div>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-48" data-testid="select-status-filter">
                    <SelectValue placeholder="Filtrar por status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Status</SelectItem>
                    <SelectItem value="pending">Pendente</SelectItem>
                    <SelectItem value="running">Executando</SelectItem>
                    <SelectItem value="completed">Concluído</SelectItem>
                    <SelectItem value="failed">Falhou</SelectItem>
                    <SelectItem value="timeout">Timeout</SelectItem>
                  </SelectContent>
                </Select>
                <Badge variant="secondary" data-testid="jobs-count">
                  {filteredJobs.length} jobs
                </Badge>
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Jobs Table */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>Lista de Jobs</CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="text-center py-8">
                    <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                    <p className="text-muted-foreground">Carregando jobs...</p>
                  </div>
                ) : filteredJobs.length === 0 ? (
                  <div className="text-center py-8">
                    <RefreshCw className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                    <h3 className="text-lg font-medium text-foreground mb-2">
                      {searchTerm || statusFilter !== "all" ? 'Nenhum job encontrado' : 'Nenhum job executado'}
                    </h3>
                    <p className="text-muted-foreground">
                      {searchTerm || statusFilter !== "all" 
                        ? 'Tente ajustar os filtros de busca'
                        : 'Execute jornadas para ver jobs aqui'
                      }
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {filteredJobs.map((job) => {
                      const StatusIcon = getStatusIcon(job.status);
                      return (
                        <div
                          key={job.id}
                          className={`p-4 border rounded-lg cursor-pointer transition-colors hover:bg-muted/50 ${
                            selectedJob?.id === job.id ? 'border-primary bg-primary/5' : 'border-border'
                          }`}
                          onClick={() => handleViewJob(job)}
                          data-testid={`job-item-${job.id}`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <StatusIcon className={`h-4 w-4 ${job.status === 'running' ? 'animate-spin' : ''}`} />
                              <Badge className={getStatusColor(job.status)}>
                                {getStatusLabel(job.status)}
                              </Badge>
                              <span className="text-sm text-muted-foreground font-mono">
                                ID: {job.id.slice(0, 8)}...
                              </span>
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {formatDuration(job.startedAt?.toString(), job.finishedAt?.toString())}
                            </span>
                          </div>
                          
                          {job.status === 'running' && (
                            <div className="mb-2">
                              <div className="flex justify-between text-sm mb-1">
                                <span className="text-muted-foreground">
                                  {job.currentTask || 'Executando...'}
                                </span>
                                <span>{job.progress || 0}%</span>
                              </div>
                              <Progress value={job.progress || 0} className="h-2" />
                            </div>
                          )}
                          
                          <p className="text-sm text-muted-foreground">
                            Criado: {new Date(job.createdAt).toLocaleString('pt-BR')}
                          </p>
                          
                          {job.error && (
                            <p className="text-sm text-destructive mt-1">
                              Erro: {job.error}
                            </p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Job Details */}
            <Card>
              <CardHeader>
                <CardTitle>Detalhes do Job</CardTitle>
              </CardHeader>
              <CardContent>
                {!selectedJob ? (
                  <div className="text-center py-8">
                    <Eye className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                    <h3 className="text-lg font-medium text-foreground mb-2">
                      Selecione um Job
                    </h3>
                    <p className="text-muted-foreground">
                      Clique em um job na lista para ver os detalhes
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-medium text-foreground mb-2">Informações Básicas</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">ID:</span>
                          <span className="font-mono">{selectedJob.id}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Status:</span>
                          <Badge className={getStatusColor(selectedJob.status)}>
                            {getStatusLabel(selectedJob.status)}
                          </Badge>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Progresso:</span>
                          <span>{selectedJob.progress || 0}%</span>
                        </div>
                        {selectedJob.currentTask && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Tarefa:</span>
                            <span>{selectedJob.currentTask}</span>
                          </div>
                        )}
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Duração:</span>
                          <span>{formatDuration(selectedJob.startedAt?.toString(), selectedJob.finishedAt?.toString())}</span>
                        </div>
                      </div>
                    </div>

                    {selectedJob.error && (
                      <div>
                        <h4 className="font-medium text-foreground mb-2">Erro</h4>
                        <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                          <p className="text-sm text-destructive">{selectedJob.error}</p>
                        </div>
                      </div>
                    )}

                    {isLoadingResult ? (
                      <div className="text-center py-4">
                        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                        <p className="text-sm text-muted-foreground">Carregando resultado...</p>
                      </div>
                    ) : jobResult ? (
                      <div className="space-y-4">
                        {jobResult.stdout && (
                          <div>
                            <h4 className="font-medium text-foreground mb-2">Saída</h4>
                            <div className="p-3 bg-muted/50 border rounded-md">
                              <pre className="text-xs text-muted-foreground whitespace-pre-wrap">
                                {jobResult.stdout}
                              </pre>
                            </div>
                          </div>
                        )}

                        {jobResult.stderr && (
                          <div>
                            <h4 className="font-medium text-foreground mb-2">Erros</h4>
                            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                              <pre className="text-xs text-destructive whitespace-pre-wrap">
                                {jobResult.stderr}
                              </pre>
                            </div>
                          </div>
                        )}

                        {jobResult.artifacts?.statistics && jobResult.artifacts?.findings && (
                          <div>
                            <h4 className="font-medium text-foreground mb-2">Artefatos</h4>
                            <div className="space-y-4 mb-4">
                              <div className="p-4 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-md">
                                <h5 className="font-medium text-blue-900 dark:text-blue-100 mb-3">📊 Estatísticas de Amostragem EDR/AV</h5>
                                <div className="grid grid-cols-2 gap-4 text-sm">
                                  <div>
                                    <span className="text-blue-700 dark:text-blue-300 font-medium">Computadores descobertos:</span>
                                    <div className="text-lg font-bold text-blue-900 dark:text-blue-100">
                                      {jobResult.artifacts.statistics.totalDiscovered || 0}
                                    </div>
                                  </div>
                                  <div>
                                    <span className="text-blue-700 dark:text-blue-300 font-medium">Amostragem solicitada:</span>
                                    <div className="text-lg font-bold text-blue-900 dark:text-blue-100">
                                      {jobResult.artifacts.statistics.requestedSampleRate || 0}% ({jobResult.artifacts.statistics.requestedSampleSize || 0} computadores)
                                    </div>
                                  </div>
                                  <div>
                                    <span className="text-blue-700 dark:text-blue-300 font-medium">Computadores testados:</span>
                                    <div className="text-lg font-bold text-blue-900 dark:text-blue-100">
                                      {jobResult.artifacts.statistics.successfulDeployments || 0}
                                    </div>
                                  </div>
                                  <div>
                                    <span className="text-blue-700 dark:text-blue-300 font-medium">Cobertura de amostra:</span>
                                    <div className="text-lg font-bold text-blue-900 dark:text-blue-100">
                                      {jobResult.artifacts.statistics.successfulDeployments && jobResult.artifacts.statistics.requestedSampleSize 
                                        ? Math.round((jobResult.artifacts.statistics.successfulDeployments / Math.max(1, jobResult.artifacts.statistics.requestedSampleSize)) * 100) 
                                        : 0}%
                                    </div>
                                  </div>
                                </div>
                                
                                {jobResult.artifacts.statistics.failedDeployments > 0 && (
                                  <div className="mt-3 pt-3 border-t border-blue-200 dark:border-blue-800">
                                    <div className="flex items-center justify-between text-sm">
                                      <span className="text-orange-700 dark:text-orange-300">🔄 Falhas no deploy:</span>
                                      <span className="font-medium text-orange-900 dark:text-orange-100">
                                        {jobResult.artifacts.statistics.failedDeployments}
                                      </span>
                                    </div>
                                  </div>
                                )}
                                
                                {jobResult.artifacts.statistics.successfulDeployments > 0 && (
                                  <div className="mt-3 pt-3 border-t border-blue-200 dark:border-blue-800">
                                    <div className="mb-3">
                                      <div className="flex items-center justify-between text-sm mb-1">
                                        <span className="text-blue-700 dark:text-blue-300 font-medium">Efetividade EDR/AV:</span>
                                        <span className="font-bold text-blue-900 dark:text-blue-100">
                                          {Math.round(((jobResult.artifacts.statistics.eicarRemovedCount || 0) / jobResult.artifacts.statistics.successfulDeployments) * 100)}%
                                        </span>
                                      </div>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4 text-sm">
                                      <div className="flex items-center justify-between">
                                        <span className="text-green-700 dark:text-green-300 font-medium">✅ EDR/AV funcionou:</span>
                                        <span className="font-bold text-green-900 dark:text-green-100">
                                          {jobResult.artifacts.statistics.eicarRemovedCount || 0}
                                        </span>
                                      </div>
                                      <div className="flex items-center justify-between">
                                        <span className="text-red-700 dark:text-red-300 font-medium">⚠️ Falhas EDR/AV:</span>
                                        <span className="font-bold text-red-900 dark:text-red-100">
                                          {jobResult.artifacts.statistics.eicarPersistedCount || 0}
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    ) : selectedJob.status === 'completed' ? (
                      <div className="text-center py-4">
                        <p className="text-sm text-muted-foreground">
                          Nenhum resultado disponível para este job
                        </p>
                      </div>
                    ) : null}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
