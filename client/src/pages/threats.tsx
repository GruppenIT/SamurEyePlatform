import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Search, AlertTriangle, Eye, CheckCircle, Clock, Shield } from "lucide-react";
import { Threat } from "@shared/schema";
import { ThreatStats } from "@/types";

export default function Threats() {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: threats = [], isLoading } = useQuery<Threat[]>({
    queryKey: ["/api/threats", { severity: severityFilter !== "all" ? severityFilter : undefined, status: statusFilter !== "all" ? statusFilter : undefined }],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: stats } = useQuery<ThreatStats>({
    queryKey: ["/api/threats/stats"],
    refetchInterval: 30000,
  });

  const updateThreatMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<Threat> }) => {
      return await apiRequest('PATCH', `/api/threats/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Ameaça atualizada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats/stats"] });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Não autorizado",
          description: "Você foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: "Falha ao atualizar ameaça",
        variant: "destructive",
      });
    },
  });

  const filteredThreats = threats.filter(threat => {
    const matchesSearch = threat.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (threat.description && threat.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesSeverity = severityFilter === "all" || threat.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || threat.status === statusFilter;
    
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-destructive text-destructive-foreground';
      case 'high':
        return 'bg-orange-600 text-white';
      case 'medium':
        return 'bg-accent text-accent-foreground';
      case 'low':
        return 'bg-chart-4 text-white';
      default:
        return 'bg-muted text-muted-foreground';
    }
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return 'bg-destructive/20 text-destructive';
      case 'investigating':
        return 'bg-accent/20 text-accent';
      case 'mitigated':
        return 'bg-primary/20 text-primary';
      case 'closed':
        return 'bg-chart-4/20 text-chart-4';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'open':
        return 'Aberta';
      case 'investigating':
        return 'Investigando';
      case 'mitigated':
        return 'Mitigada';
      case 'closed':
        return 'Fechada';
      default:
        return status;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return AlertTriangle;
      case 'investigating':
        return Clock;
      case 'mitigated':
      case 'closed':
        return CheckCircle;
      default:
        return AlertTriangle;
    }
  };

  const handleStatusChange = (threat: Threat, newStatus: string) => {
    updateThreatMutation.mutate({
      id: threat.id,
      data: { status: newStatus as any }
    });
  };

  const formatTimeAgo = (date: string) => {
    const now = new Date();
    const threatDate = new Date(date);
    const diffInMinutes = Math.floor((now.getTime() - threatDate.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 60) {
      return `${diffInMinutes}m atrás`;
    } else if (diffInMinutes < 24 * 60) {
      return `${Math.floor(diffInMinutes / 60)}h atrás`;
    } else {
      return `${Math.floor(diffInMinutes / (24 * 60))}d atrás`;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Threat Intelligence"
          subtitle="Gerencie e analise ameaças identificadas pelo sistema"
        />
        
        <div className="p-6 space-y-6">
          {/* Stats Overview */}
          {stats && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
              <Card className="metric-card">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total</p>
                      <p className="text-2xl font-bold text-foreground">{stats.total}</p>
                    </div>
                    <Shield className="h-8 w-8 text-primary" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="metric-card">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Críticas</p>
                      <p className="text-2xl font-bold text-destructive">{stats.critical}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-destructive" />
                  </div>
                </CardContent>
              </Card>

              <Card className="metric-card">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Altas</p>
                      <p className="text-2xl font-bold text-orange-500">{stats.high}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-orange-500" />
                  </div>
                </CardContent>
              </Card>

              <Card className="metric-card">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Médias</p>
                      <p className="text-2xl font-bold text-accent">{stats.medium}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-accent" />
                  </div>
                </CardContent>
              </Card>

              <Card className="metric-card">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Baixas</p>
                      <p className="text-2xl font-bold text-chart-4">{stats.low}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-chart-4" />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar ameaças por título ou descrição..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-threats"
                  />
                </div>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-48" data-testid="select-severity-filter">
                    <SelectValue placeholder="Filtrar por severidade" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todas as Severidades</SelectItem>
                    <SelectItem value="critical">Crítica</SelectItem>
                    <SelectItem value="high">Alta</SelectItem>
                    <SelectItem value="medium">Média</SelectItem>
                    <SelectItem value="low">Baixa</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-48" data-testid="select-status-filter">
                    <SelectValue placeholder="Filtrar por status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Status</SelectItem>
                    <SelectItem value="open">Aberta</SelectItem>
                    <SelectItem value="investigating">Investigando</SelectItem>
                    <SelectItem value="mitigated">Mitigada</SelectItem>
                    <SelectItem value="closed">Fechada</SelectItem>
                  </SelectContent>
                </Select>
                <Badge variant="secondary" data-testid="threats-count">
                  {filteredThreats.length} ameaças
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Threats Table */}
          <Card>
            <CardHeader>
              <CardTitle>Ameaças Identificadas</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando ameaças...</p>
                </div>
              ) : filteredThreats.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm || severityFilter !== "all" || statusFilter !== "all" ? 
                      'Nenhuma ameaça encontrada' : 'Nenhuma ameaça identificada'
                    }
                  </h3>
                  <p className="text-muted-foreground">
                    {searchTerm || severityFilter !== "all" || statusFilter !== "all" 
                      ? 'Tente ajustar os filtros de busca'
                      : 'Execute jornadas para identificar ameaças'
                    }
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severidade</TableHead>
                      <TableHead>Título</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Detectado em</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredThreats.map((threat) => {
                      const StatusIcon = getStatusIcon(threat.status);
                      return (
                        <TableRow key={threat.id} data-testid={`threat-row-${threat.id}`}>
                          <TableCell>
                            <Badge className={getSeverityColor(threat.severity)}>
                              {getSeverityLabel(threat.severity)}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-md">
                            <div>
                              <p className="font-medium text-foreground">{threat.title}</p>
                              {threat.description && (
                                <p className="text-sm text-muted-foreground truncate">
                                  {threat.description}
                                </p>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <StatusIcon className="h-4 w-4" />
                              <Select
                                value={threat.status}
                                onValueChange={(value) => handleStatusChange(threat, value)}
                                disabled={updateThreatMutation.isPending}
                              >
                                <SelectTrigger className="w-32 h-8">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="open">Aberta</SelectItem>
                                  <SelectItem value="investigating">Investigando</SelectItem>
                                  <SelectItem value="mitigated">Mitigada</SelectItem>
                                  <SelectItem value="closed">Fechada</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {formatTimeAgo(threat.createdAt)}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setSelectedThreat(threat)}
                              data-testid={`button-view-${threat.id}`}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Threat Details Dialog */}
      <Dialog open={!!selectedThreat} onOpenChange={() => setSelectedThreat(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Detalhes da Ameaça</DialogTitle>
          </DialogHeader>
          {selectedThreat && (
            <div className="space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-xl font-semibold text-foreground mb-2">
                    {selectedThreat.title}
                  </h3>
                  <div className="flex items-center space-x-2 mb-4">
                    <Badge className={getSeverityColor(selectedThreat.severity)}>
                      {getSeverityLabel(selectedThreat.severity)}
                    </Badge>
                    <Badge className={getStatusColor(selectedThreat.status)}>
                      {getStatusLabel(selectedThreat.status)}
                    </Badge>
                  </div>
                </div>
              </div>

              {selectedThreat.description && (
                <div>
                  <h4 className="font-medium text-foreground mb-2">Descrição</h4>
                  <p className="text-muted-foreground">{selectedThreat.description}</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-foreground mb-2">Informações</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Fonte:</span>
                      <span>{selectedThreat.source}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Detectado em:</span>
                      <span>{new Date(selectedThreat.createdAt).toLocaleString('pt-BR')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Atualizado em:</span>
                      <span>{new Date(selectedThreat.updatedAt).toLocaleString('pt-BR')}</span>
                    </div>
                  </div>
                </div>
              </div>

              {selectedThreat.evidence && Object.keys(selectedThreat.evidence).length > 0 && (
                <div>
                  <h4 className="font-medium text-foreground mb-2">Evidências</h4>
                  <div className="p-4 bg-muted/50 border rounded-md">
                    <pre className="text-sm text-muted-foreground whitespace-pre-wrap">
                      {JSON.stringify(selectedThreat.evidence, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
