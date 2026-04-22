import { useState, useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useWebSocket } from "@/lib/websocket";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Search, Eye, RefreshCw, Clock, CheckCircle, XCircle, AlertCircle, X, Cpu } from "lucide-react";
import { Job, JobResult } from "@shared/schema";
import { JobUpdate } from "@/types";

export default function Jobs() {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);
  const [cancelJobId, setCancelJobId] = useState<string | null>(null);

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { lastMessage, connected } = useWebSocket();
  const prevStatusRef = useRef<Map<string, string>>(new Map());

  const { data: jobs = [], isLoading, refetch } = useQuery<Job[]>({
    queryKey: ["/api/jobs"],
    refetchInterval: 5000,
  });

  const { data: jobResult, isLoading: isLoadingResult } = useQuery<JobResult>({
    queryKey: [`/api/jobs/${selectedJob?.id}/result`],
    enabled: !!selectedJob && selectedJob.status !== 'running' && selectedJob.status !== 'pending',
    retry: false,
  });

  // Handle WebSocket job updates - only toast on terminal status changes
  useEffect(() => {
    if (lastMessage && lastMessage.type === 'jobUpdate') {
      const update = lastMessage.data as JobUpdate;
      const prevStatus = prevStatusRef.current.get(update.jobId);

      // Only show toast when status changes to a terminal state
      if (update.status !== prevStatus && ['completed', 'failed', 'timeout'].includes(update.status)) {
        const labels: Record<string, string> = {
          completed: 'concluido',
          failed: 'falhou',
          timeout: 'timeout',
        };
        toast({
          title: `Job ${labels[update.status] || update.status}`,
          description: `Job ${update.jobId.slice(0, 8)}... ${labels[update.status] || update.status}`,
          variant: update.status === 'completed' ? 'default' : 'destructive',
        });
      }

      prevStatusRef.current.set(update.jobId, update.status);

      // Silently refresh job list
      refetch();

      // Update selected job in-place if it matches
      if (selectedJob && update.jobId === selectedJob.id) {
        setSelectedJob(prev => prev ? {
          ...prev,
          status: update.status as Job['status'],
          progress: update.progress ?? prev.progress,
          currentTask: update.currentTask ?? prev.currentTask,
        } : null);
      }
    }
  }, [lastMessage]);

  // Cancel job handler
  const handleCancelJob = async (jobId: string) => {
    try {
      await apiRequest('POST', `/api/jobs/${jobId}/cancel-process`);
      toast({
        title: "Job cancelado",
        description: "Os processos em execucao serao interrompidos.",
      });
      refetch();
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/running-jobs"] });
    } catch (error) {
      toast({
        title: "Erro ao cancelar",
        description: "Nao foi possivel cancelar o job.",
        variant: "destructive",
      });
    }
  };

  const filteredJobs = jobs.filter(job => {
    const matchesSearch = job.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (job.currentTask && job.currentTask.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesStatus = statusFilter === "all" || job.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return Clock;
      case 'running': return RefreshCw;
      case 'completed': return CheckCircle;
      case 'failed': return XCircle;
      case 'timeout': return AlertCircle;
      default: return Clock;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'bg-muted text-muted-foreground';
      case 'running': return 'bg-primary/20 text-primary';
      case 'completed': return 'bg-chart-4/20 text-chart-4';
      case 'failed': return 'bg-destructive/20 text-destructive';
      case 'timeout': return 'bg-accent/20 text-accent';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'pending': return 'Pendente';
      case 'running': return 'Executando';
      case 'completed': return 'Concluido';
      case 'failed': return 'Falhou';
      case 'timeout': return 'Timeout';
      default: return status;
    }
  };

  const formatDuration = (start?: string | Date | null, end?: string | Date | null) => {
    if (!start) return '-';
    const startTime = new Date(start);
    const endTime = end ? new Date(end) : new Date();
    const duration = Math.floor((endTime.getTime() - startTime.getTime()) / 1000);
    if (duration < 60) return `${duration}s`;
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    if (minutes < 60) return `${minutes}m ${seconds}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  };

  // Extract PID info from currentTask string
  const extractPidInfo = (currentTask?: string | null) => {
    if (!currentTask) return null;
    const match = currentTask.match(/\((nmap|nuclei) pid (\d+)\)/);
    if (match) {
      return { processName: match[1], pid: match[2], stage: currentTask.replace(match[0], '').trim() };
    }
    return null;
  };

  const handleViewJob = (job: Job) => {
    setSelectedJob(job);
  };

  // Keep selectedJob in sync with refreshed jobs list
  useEffect(() => {
    if (selectedJob && jobs.length > 0) {
      const updated = jobs.find(j => j.id === selectedJob.id);
      if (updated) setSelectedJob(updated);
    }
  }, [jobs]);

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <main className="flex-1 overflow-hidden">
        <TopBar
          title="Monitoramento de Jobs"
          subtitle="Acompanhe execucoes e resultados das jornadas"
          wsConnected={connected}
        />

        <div className="p-6 space-y-6 overflow-auto h-[calc(100%-4rem)]">
          {/* Search and Filters */}
          <div className="flex items-center gap-4">
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
                <SelectItem value="running">Executando</SelectItem>
                <SelectItem value="completed">Concluido</SelectItem>
                <SelectItem value="failed">Falhou</SelectItem>
                <SelectItem value="timeout">Timeout</SelectItem>
                <SelectItem value="pending">Pendente</SelectItem>
              </SelectContent>
            </Select>
            <Badge variant="secondary" data-testid="jobs-count">
              {filteredJobs.length} jobs
            </Badge>
            <Button
              onClick={() => refetch()}
              disabled={isLoading}
              data-testid="button-refresh-jobs"
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Atualizar
            </Button>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Jobs List */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Lista de Jobs</CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="text-center py-8">
                    <RefreshCw className="mx-auto h-8 w-8 text-muted-foreground animate-spin mb-3" />
                    <p className="text-sm text-muted-foreground">Carregando jobs...</p>
                  </div>
                ) : filteredJobs.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-sm text-muted-foreground">
                      {searchTerm || statusFilter !== "all" ? 'Nenhum job encontrado' : 'Nenhum job executado'}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[calc(100vh-18rem)] overflow-y-auto">
                    {filteredJobs.map((job) => {
                      const StatusIcon = getStatusIcon(job.status);
                      const pidInfo = extractPidInfo(job.currentTask);
                      const isSelected = selectedJob?.id === job.id;

                      return (
                        <div
                          key={job.id}
                          className={`p-3 border rounded-lg cursor-pointer transition-colors hover:bg-muted/50 ${
                            isSelected ? 'border-primary bg-primary/5' : 'border-border'
                          }`}
                          onClick={() => handleViewJob(job)}
                          data-testid={`job-item-${job.id}`}
                        >
                          {/* Header: status + ID + duration + cancel */}
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <StatusIcon className={`h-4 w-4 ${job.status === 'running' ? 'animate-spin text-primary' : 'text-muted-foreground'}`} />
                              <Badge className={getStatusColor(job.status)}>
                                {getStatusLabel(job.status)}
                              </Badge>
                              <span className="text-xs text-muted-foreground font-mono">
                                {job.id.slice(0, 8)}
                              </span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground">
                                {formatDuration(job.startedAt, job.finishedAt)}
                              </span>
                              {job.status === 'running' && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 text-destructive hover:text-destructive hover:bg-destructive/10"
                                  onClick={(e) => { e.stopPropagation(); setCancelJobId(job.id); }}
                                  data-testid={`button-cancel-${job.id}`}
                                >
                                  <X className="h-3.5 w-3.5" />
                                </Button>
                              )}
                            </div>
                          </div>

                          {/* Running: task + progress bar */}
                          {job.status === 'running' && (
                            <div className="mt-2">
                              <div className="flex items-center justify-between text-xs mb-1">
                                <span className="text-muted-foreground truncate mr-2">
                                  {pidInfo?.stage || job.currentTask || 'Executando...'}
                                </span>
                                <span className="text-foreground font-medium shrink-0">{job.progress || 0}%</span>
                              </div>
                              <Progress value={job.progress || 0} className="h-1.5" />
                              {pidInfo && (
                                <div className="flex items-center gap-1.5 mt-1.5">
                                  <Cpu className="h-3 w-3 text-muted-foreground" />
                                  <span className="text-[10px] font-mono text-muted-foreground">
                                    {pidInfo.processName} pid {pidInfo.pid}
                                  </span>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Finished: date + error */}
                          {job.status !== 'running' && (
                            <p className="text-xs text-muted-foreground mt-1">
                              {new Date(job.createdAt).toLocaleString('pt-BR')}
                            </p>
                          )}

                          {job.error && (
                            <p className="text-xs text-destructive mt-1 truncate">
                              {job.error}
                            </p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Job Details Panel */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Detalhes do Job</CardTitle>
              </CardHeader>
              <CardContent className="max-h-[calc(100vh-18rem)] overflow-y-auto">
                {!selectedJob ? (
                  <div className="text-center py-8">
                    <Eye className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
                    <p className="text-sm text-muted-foreground">
                      Selecione um job na lista
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Progress for running jobs */}
                    {selectedJob.status === 'running' && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{selectedJob.progress || 0}%</span>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => setCancelJobId(selectedJob.id)}
                            data-testid="button-cancel-selected"
                          >
                            <X className="h-3.5 w-3.5 mr-1" />
                            Cancelar
                          </Button>
                        </div>
                        <Progress value={selectedJob.progress || 0} className="h-2" />
                        {selectedJob.currentTask && (
                          <p className="text-xs text-muted-foreground">{selectedJob.currentTask}</p>
                        )}
                      </div>
                    )}

                    {/* Basic info */}
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-muted-foreground">Status</span>
                        <Badge className={getStatusColor(selectedJob.status)}>
                          {getStatusLabel(selectedJob.status)}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">ID</span>
                        <span className="font-mono text-xs">{selectedJob.id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Jornada</span>
                        <span className="font-mono text-xs">{selectedJob.journeyId.slice(0, 8)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Duracao</span>
                        <span>{formatDuration(selectedJob.startedAt, selectedJob.finishedAt)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Criado</span>
                        <span className="text-xs">{new Date(selectedJob.createdAt).toLocaleString('pt-BR')}</span>
                      </div>
                      {selectedJob.startedAt && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Inicio</span>
                          <span className="text-xs">{new Date(selectedJob.startedAt).toLocaleString('pt-BR')}</span>
                        </div>
                      )}
                      {selectedJob.finishedAt && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Termino</span>
                          <span className="text-xs">{new Date(selectedJob.finishedAt).toLocaleString('pt-BR')}</span>
                        </div>
                      )}
                    </div>

                    {/* Error */}
                    {selectedJob.error && (
                      <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                        <p className="text-xs text-destructive">{selectedJob.error}</p>
                      </div>
                    )}

                    {/* Job Result */}
                    {isLoadingResult ? (
                      <div className="text-center py-4">
                        <RefreshCw className="mx-auto h-5 w-5 text-muted-foreground animate-spin mb-2" />
                        <p className="text-xs text-muted-foreground">Carregando resultado...</p>
                      </div>
                    ) : jobResult ? (
                      <div className="space-y-3">
                        {jobResult.stdout && (
                          <div>
                            <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-2">Saida</h4>
                            <div className="p-2 bg-muted/50 border rounded-md">
                              <pre className="text-xs text-muted-foreground whitespace-pre-wrap break-words">
                                {jobResult.stdout}
                              </pre>
                            </div>
                          </div>
                        )}

                        {jobResult.stderr && (
                          <div>
                            <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-2">Erros</h4>
                            <div className="p-2 bg-destructive/10 border border-destructive/20 rounded-md">
                              <pre className="text-xs text-destructive whitespace-pre-wrap break-words">
                                {jobResult.stderr}
                              </pre>
                            </div>
                          </div>
                        )}

                        {jobResult.artifacts && Object.keys(jobResult.artifacts).length > 0 && (
                          <div>
                            <h4 className="text-xs font-semibold text-foreground uppercase tracking-wider mb-2">Artefatos</h4>

                            {/* EDR/AV Statistics */}
                            {jobResult.artifacts?.statistics && jobResult.artifacts?.findings && (
                              <div className="p-3 bg-primary/5 border border-primary/20 rounded-md mb-2 space-y-2">
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  <div>
                                    <span className="text-muted-foreground">Descobertos:</span>
                                    <span className="ml-1 font-medium">{jobResult.artifacts.statistics.totalDiscovered || 0}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Testados:</span>
                                    <span className="ml-1 font-medium">{jobResult.artifacts.statistics.successfulDeployments || 0}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Amostragem:</span>
                                    <span className="ml-1 font-medium">{jobResult.artifacts.statistics.requestedSampleRate || 0}%</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Efetividade:</span>
                                    <span className="ml-1 font-medium">
                                      {jobResult.artifacts.statistics.successfulDeployments > 0
                                        ? `${Math.round(((jobResult.artifacts.statistics.eicarRemovedCount || 0) / jobResult.artifacts.statistics.successfulDeployments) * 100)}%`
                                        : '-'}
                                    </span>
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Summary for attack_surface */}
                            {jobResult.artifacts?.summary && (
                              <div className="p-3 bg-primary/5 border border-primary/20 rounded-md mb-2">
                                <div className="grid grid-cols-2 gap-2 text-xs">
                                  <div>
                                    <span className="text-muted-foreground">Alvos:</span>
                                    <span className="ml-1 font-medium">{jobResult.artifacts.summary.totalAssets || 0}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Achados:</span>
                                    <span className="ml-1 font-medium">{jobResult.artifacts.summary.totalFindings || 0}</span>
                                  </div>
                                  {jobResult.artifacts.summary.webApplicationsDiscovered > 0 && (
                                    <div>
                                      <span className="text-muted-foreground">Web Apps:</span>
                                      <span className="ml-1 font-medium">{jobResult.artifacts.summary.webApplicationsDiscovered}</span>
                                    </div>
                                  )}
                                  {jobResult.artifacts.summary.webScanEnabled && (
                                    <div>
                                      <span className="text-muted-foreground">Nuclei:</span>
                                      <span className="ml-1 font-medium text-primary">Habilitado</span>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            {/* Raw artifacts (collapsible) */}
                            <details className="text-xs">
                              <summary className="cursor-pointer text-muted-foreground hover:text-foreground mb-1">
                                JSON completo
                              </summary>
                              <div className="p-2 bg-muted/50 border rounded-md max-h-60 overflow-auto">
                                <pre className="text-[10px] text-muted-foreground whitespace-pre-wrap break-words">
                                  {JSON.stringify(jobResult.artifacts, null, 2)}
                                </pre>
                              </div>
                            </details>
                          </div>
                        )}
                      </div>
                    ) : selectedJob.status === 'completed' ? (
                      <p className="text-xs text-muted-foreground text-center py-2">
                        Nenhum resultado disponivel
                      </p>
                    ) : null}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* Cancel Confirmation Dialog */}
      <AlertDialog open={!!cancelJobId} onOpenChange={(open) => !open && setCancelJobId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancelar Job</AlertDialogTitle>
            <AlertDialogDescription>
              Os processos em execucao (nmap, nuclei, etc.) serao interrompidos e os resultados parciais descartados.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Voltar</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (cancelJobId) {
                  handleCancelJob(cancelJobId);
                  setCancelJobId(null);
                }
              }}
            >
              Cancelar Job
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
