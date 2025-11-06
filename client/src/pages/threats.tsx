import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
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
import { Threat, Host } from "@shared/schema";
import { ThreatStats } from "@/types";

export default function Threats() {
  const [location] = useLocation();
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [hostFilter, setHostFilter] = useState<string>("all");
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [statusChangeModal, setStatusChangeModal] = useState<{
    threat: Threat | null;
    isOpen: boolean;
    newStatus: string;
    justification: string;
    hibernatedUntil: string;
  }>({
    threat: null,
    isOpen: false,
    newStatus: '',
    justification: '',
    hibernatedUntil: '',
  });
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Initialize filters from URL parameters
  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const hostId = searchParams.get('hostId');
    const severity = searchParams.get('severity');
    const status = searchParams.get('status');
    
    if (hostId) {
      setHostFilter(hostId);
    }
    if (severity) {
      setSeverityFilter(severity);
    }
    if (status) {
      setStatusFilter(status);
    }
  }, [location]);

  const { data: threats = [], isLoading } = useQuery<(Threat & { host?: Host })[]>({
    queryKey: ["/api/threats"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });


  const { data: globalStats } = useQuery<ThreatStats>({
    queryKey: ["/api/threats/stats"],
    refetchInterval: 30000,
  });

  // Calculate filtered stats based on active filters
  const stats = useMemo(() => {
    if (!threats || threats.length === 0) {
      return globalStats || { 
        total: 0, critical: 0, high: 0, medium: 0, low: 0,
        open: 0, investigating: 0, mitigated: 0, closed: 0, hibernated: 0, accepted_risk: 0
      };
    }

    // Apply filters
    const filtered = threats.filter(t => {
      if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && t.status !== statusFilter) return false;
      if (hostFilter !== 'all' && t.hostId !== hostFilter) return false;
      return true;
    });

    // Calculate stats from filtered threats
    const calculatedStats = {
      total: filtered.length,
      critical: filtered.filter(t => t.severity === 'critical').length,
      high: filtered.filter(t => t.severity === 'high').length,
      medium: filtered.filter(t => t.severity === 'medium').length,
      low: filtered.filter(t => t.severity === 'low').length,
      open: filtered.filter(t => t.status === 'open').length,
      investigating: filtered.filter(t => t.status === 'investigating').length,
      mitigated: filtered.filter(t => t.status === 'mitigated').length,
      closed: filtered.filter(t => t.status === 'closed').length,
      hibernated: filtered.filter(t => t.status === 'hibernated').length,
      accepted_risk: filtered.filter(t => t.status === 'accepted_risk').length,
    };

    return calculatedStats;
  }, [threats, severityFilter, statusFilter, hostFilter, globalStats]);

  const { data: hosts = [] } = useQuery<Host[]>({
    queryKey: ["/api/hosts"],
    refetchInterval: 60000, // Refresh every minute
  });

  // Fetch threat status history when a threat is selected
  const { data: statusHistory = [], isLoading: isLoadingHistory } = useQuery<any[]>({
    queryKey: [`/api/threats/${selectedThreat?.id}/history`],
    enabled: !!selectedThreat,
    refetchInterval: 10000, // Refresh every 10 seconds when modal is open
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
      // Invalidate status history for the selected threat
      if (selectedThreat) {
        queryClient.invalidateQueries({ queryKey: [`/api/threats/${selectedThreat.id}/history`] });
      }
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

  const changeStatusMutation = useMutation({
    mutationFn: async ({ 
      id, 
      status, 
      justification, 
      hibernatedUntil 
    }: { 
      id: string; 
      status: string; 
      justification: string; 
      hibernatedUntil?: string; 
    }) => {
      const data: any = { status, justification };
      if (hibernatedUntil) {
        data.hibernatedUntil = hibernatedUntil;
      }
      return await apiRequest('PATCH', `/api/threats/${id}/status`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Status da ameaça atualizado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats/stats"] });
      // Invalidate status history for the specific threat
      if (statusChangeModal.threat) {
        queryClient.invalidateQueries({ queryKey: [`/api/threats/${statusChangeModal.threat.id}/history`] });
      }
      // Close modal
      setStatusChangeModal({
        threat: null,
        isOpen: false,
        newStatus: '',
        justification: '',
        hibernatedUntil: '',
      });
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
        description: "Falha ao alterar status da ameaça",
        variant: "destructive",
      });
    },
  });

  const filteredThreats = threats.filter(threat => {
    // Search filter
    const matchesSearch = threat.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (threat.description && threat.description.toLowerCase().includes(searchTerm.toLowerCase()));
    
    // Severity filter
    const matchesSeverity = severityFilter === 'all' || threat.severity === severityFilter;
    
    // Status filter
    const matchesStatus = statusFilter === 'all' || threat.status === statusFilter;
    
    // Host filter
    const matchesHost = hostFilter === 'all' || threat.hostId === hostFilter;
    
    return matchesSearch && matchesSeverity && matchesStatus && matchesHost;
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
      case 'hibernated':
        return 'bg-amber-500/20 text-amber-600';
      case 'accepted_risk':
        return 'bg-blue-500/20 text-blue-600';
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
      case 'hibernated':
        return 'Hibernada';
      case 'accepted_risk':
        return 'Risco Aceito';
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
      case 'accepted_risk':
        return Shield;
      default:
        return AlertTriangle;
    }
  };

  const handleStatusChange = (threat: Threat, newStatus: string) => {
    setStatusChangeModal({
      threat,
      isOpen: true,
      newStatus,
      justification: '',
      hibernatedUntil: '',
    });
  };

  const handleStatusSubmit = () => {
    if (!statusChangeModal.threat || !statusChangeModal.justification.trim()) {
      toast({
        title: "Erro",
        description: "Justificativa é obrigatória",
        variant: "destructive",
      });
      return;
    }

    if (statusChangeModal.newStatus === 'hibernated' && !statusChangeModal.hibernatedUntil) {
      toast({
        title: "Erro",
        description: "Data limite é obrigatória para hibernação",
        variant: "destructive",
      });
      return;
    }

    const hibernatedUntilISO = statusChangeModal.hibernatedUntil 
      ? new Date(statusChangeModal.hibernatedUntil).toISOString()
      : undefined;

    changeStatusMutation.mutate({
      id: statusChangeModal.threat.id,
      status: statusChangeModal.newStatus,
      justification: statusChangeModal.justification,
      hibernatedUntil: hibernatedUntilISO,
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

  // Handle tile click to toggle filters
  const handleSeverityTileClick = (severity: string) => {
    setSeverityFilter(current => current === severity ? 'all' : severity);
  };

  const handleStatusTileClick = (status: string) => {
    setStatusFilter(current => current === status ? 'all' : status);
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
          {/* Stats Overview - Severity */}
          {stats && (
            <>
              <div>
                <h3 className="text-sm font-medium text-muted-foreground mb-3">Distribuição por Severidade</h3>
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
                  
                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${severityFilter === 'critical' ? 'ring-2 ring-destructive' : ''}`}
                    onClick={() => handleSeverityTileClick('critical')}
                    data-testid="tile-severity-critical"
                  >
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

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${severityFilter === 'high' ? 'ring-2 ring-orange-500' : ''}`}
                    onClick={() => handleSeverityTileClick('high')}
                    data-testid="tile-severity-high"
                  >
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

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${severityFilter === 'medium' ? 'ring-2 ring-accent' : ''}`}
                    onClick={() => handleSeverityTileClick('medium')}
                    data-testid="tile-severity-medium"
                  >
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

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${severityFilter === 'low' ? 'ring-2 ring-chart-4' : ''}`}
                    onClick={() => handleSeverityTileClick('low')}
                    data-testid="tile-severity-low"
                  >
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
              </div>

              {/* Stats Overview - Status */}
              <div>
                <h3 className="text-sm font-medium text-muted-foreground mb-3">Distribuição por Status</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'open' ? 'ring-2 ring-destructive' : ''}`}
                    onClick={() => handleStatusTileClick('open')}
                    data-testid="tile-status-open"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Abertas</p>
                          <p className="text-2xl font-bold text-destructive">{stats.open}</p>
                        </div>
                        <AlertTriangle className="h-8 w-8 text-destructive" />
                      </div>
                    </CardContent>
                  </Card>

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'investigating' ? 'ring-2 ring-accent' : ''}`}
                    onClick={() => handleStatusTileClick('investigating')}
                    data-testid="tile-status-investigating"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Investigando</p>
                          <p className="text-2xl font-bold text-accent">{stats.investigating}</p>
                        </div>
                        <Clock className="h-8 w-8 text-accent" />
                      </div>
                    </CardContent>
                  </Card>

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'mitigated' ? 'ring-2 ring-primary' : ''}`}
                    onClick={() => handleStatusTileClick('mitigated')}
                    data-testid="tile-status-mitigated"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Mitigadas</p>
                          <p className="text-2xl font-bold text-primary">{stats.mitigated}</p>
                        </div>
                        <CheckCircle className="h-8 w-8 text-primary" />
                      </div>
                    </CardContent>
                  </Card>

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'closed' ? 'ring-2 ring-chart-4' : ''}`}
                    onClick={() => handleStatusTileClick('closed')}
                    data-testid="tile-status-closed"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Fechadas</p>
                          <p className="text-2xl font-bold text-chart-4">{stats.closed}</p>
                        </div>
                        <CheckCircle className="h-8 w-8 text-chart-4" />
                      </div>
                    </CardContent>
                  </Card>

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'hibernated' ? 'ring-2 ring-amber-600' : ''}`}
                    onClick={() => handleStatusTileClick('hibernated')}
                    data-testid="tile-status-hibernated"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Hibernadas</p>
                          <p className="text-2xl font-bold text-amber-600">{stats.hibernated}</p>
                        </div>
                        <Clock className="h-8 w-8 text-amber-600" />
                      </div>
                    </CardContent>
                  </Card>

                  <Card 
                    className={`metric-card cursor-pointer transition-all hover:scale-105 ${statusFilter === 'accepted_risk' ? 'ring-2 ring-blue-600' : ''}`}
                    onClick={() => handleStatusTileClick('accepted_risk')}
                    data-testid="tile-status-accepted-risk"
                  >
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium text-muted-foreground">Risco Aceito</p>
                          <p className="text-2xl font-bold text-blue-600">{stats.accepted_risk}</p>
                        </div>
                        <Shield className="h-8 w-8 text-blue-600" />
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </>
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
                    <SelectItem value="hibernated">Hibernada</SelectItem>
                    <SelectItem value="accepted_risk">Risco Aceito</SelectItem>
                    <SelectItem value="closed">Fechada</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={hostFilter} onValueChange={setHostFilter}>
                  <SelectTrigger className="w-48" data-testid="select-host-filter">
                    <SelectValue placeholder="Filtrar por host" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Hosts</SelectItem>
                    {hosts.map(host => (
                      <SelectItem key={host.id} value={host.id}>
                        {host.name}
                      </SelectItem>
                    ))}
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
                      <TableHead>Host</TableHead>
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
                          <TableCell data-testid={`cell-host-${threat.id}`}>
                            {threat.host ? (
                              <div className="flex flex-col">
                                <span className="font-medium text-foreground">{threat.host.name}</span>
                                <span className="text-xs text-muted-foreground">
                                  {threat.host.ips?.[0] || "-"}
                                </span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-sm">N/A</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <StatusIcon className="h-4 w-4" />
                              <Select
                                value={threat.status}
                                onValueChange={(value) => handleStatusChange(threat, value)}
                                disabled={changeStatusMutation.isPending}
                              >
                                <SelectTrigger className="w-32 h-8">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="open">Aberta</SelectItem>
                                  <SelectItem value="investigating">Investigando</SelectItem>
                                  <SelectItem value="mitigated">Mitigada</SelectItem>
                                  <SelectItem value="hibernated">Hibernada</SelectItem>
                                  <SelectItem value="accepted_risk">Risco Aceito</SelectItem>
                                </SelectContent>
                              </Select>
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {formatTimeAgo(threat.createdAt.toString())}
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

              {/* Recomendação - exibir remediation ou recommendation do evidence */}
              {(selectedThreat.evidence?.remediation || selectedThreat.evidence?.recommendation) && (
                <div className="p-4 bg-orange-500/10 dark:bg-orange-950/30 border-2 border-orange-600/40 dark:border-orange-700/50 rounded-lg">
                  <h4 className="font-semibold text-orange-700 dark:text-orange-400 mb-2 flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Recomendação
                  </h4>
                  <p className="text-orange-900 dark:text-orange-100 leading-relaxed">
                    {selectedThreat.evidence.remediation || selectedThreat.evidence.recommendation}
                  </p>
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

              {/* Status History Section */}
              <div>
                <h4 className="font-medium text-foreground mb-4">Histórico de Status</h4>
                {isLoadingHistory ? (
                  <div className="text-center py-4">
                    <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                    <p className="text-sm text-muted-foreground">Carregando histórico...</p>
                  </div>
                ) : statusHistory.length > 0 ? (
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {statusHistory.map((entry: any, index: number) => (
                      <div key={index} className="p-3 bg-muted/50 border rounded-md" data-testid={`status-history-${index}`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            {entry.fromStatus && (
                              <Badge variant="outline" className="text-xs">
                                {getStatusLabel(entry.fromStatus)}
                              </Badge>
                            )}
                            <span className="text-muted-foreground text-xs">→</span>
                            <Badge className={getStatusColor(entry.toStatus) + " text-xs"}>
                              {getStatusLabel(entry.toStatus)}
                            </Badge>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(entry.changedAt || entry.createdAt).toLocaleString('pt-BR')}
                          </span>
                        </div>
                        {entry.justification && (
                          <p className="text-sm text-muted-foreground mb-2">
                            {entry.justification}
                          </p>
                        )}
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">
                            Por: {entry.changedBy?.firstName} {entry.changedBy?.lastName} ({entry.changedBy?.email})
                          </span>
                          {entry.hibernatedUntil && (
                            <span className="text-muted-foreground">
                              Hibernado até: {new Date(entry.hibernatedUntil).toLocaleString('pt-BR')}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <p className="text-sm text-muted-foreground">Sem histórico de mudanças de status ainda</p>
                  </div>
                )}
              </div>

              {selectedThreat.evidence && Object.keys(selectedThreat.evidence).length > 0 && (
                <div>
                  <h4 className="font-medium text-foreground mb-4">Evidências</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Informações de Host/IP */}
                    {(selectedThreat.evidence.host || selectedThreat.evidence.ip) && (
                      <div className="p-4 bg-muted/50 border rounded-md">
                        <h5 className="font-medium text-sm text-foreground mb-2">Localização</h5>
                        <div className="space-y-1 text-sm">
                          {selectedThreat.evidence.host && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Host:</span>
                              <span className="font-mono">{selectedThreat.evidence.host}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.ip && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">IP:</span>
                              <span className="font-mono">{selectedThreat.evidence.ip}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Informações de Porta/Serviço */}
                    {(selectedThreat.evidence.port || selectedThreat.evidence.service) && (
                      <div className="p-4 bg-muted/50 border rounded-md">
                        <h5 className="font-medium text-sm text-foreground mb-2">Serviço</h5>
                        <div className="space-y-1 text-sm">
                          {selectedThreat.evidence.port && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Porta:</span>
                              <span className="font-mono">{selectedThreat.evidence.port}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.service && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Serviço:</span>
                              <span className="font-mono">{selectedThreat.evidence.service}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.version && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Versão:</span>
                              <span className="font-mono text-xs">{selectedThreat.evidence.version}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.state && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Estado:</span>
                              <Badge variant={selectedThreat.evidence.state === 'open' ? 'destructive' : 'secondary'} className="text-xs">
                                {selectedThreat.evidence.state === 'open' ? 'ABERTA' : selectedThreat.evidence.state.toUpperCase()}
                              </Badge>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Informações do Sistema Operacional */}
                    {selectedThreat.evidence.osInfo && (
                      <div className="p-4 bg-muted/50 border rounded-md md:col-span-2">
                        <h5 className="font-medium text-sm text-foreground mb-2">Sistema Operacional</h5>
                        <p className="text-sm text-muted-foreground">{selectedThreat.evidence.osInfo}</p>
                      </div>
                    )}

                    {/* Banner/Detalhes Técnicos */}
                    {selectedThreat.evidence.banner && (
                      <div className="p-4 bg-muted/50 border rounded-md md:col-span-2">
                        <h5 className="font-medium text-sm text-foreground mb-2">Banner do Serviço</h5>
                        <pre className="text-xs text-muted-foreground whitespace-pre-wrap bg-background p-2 rounded border">
                          {selectedThreat.evidence.banner}
                        </pre>
                      </div>
                    )}

                    {/* Vulnerabilidades Web */}
                    {selectedThreat.evidence.vulnerabilityType && (
                      <div className="p-4 bg-muted/50 border rounded-md md:col-span-2">
                        <h5 className="font-medium text-sm text-foreground mb-2">Detalhes da Vulnerabilidade</h5>
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Tipo:</span>
                            <span>{selectedThreat.evidence.vulnerabilityType}</span>
                          </div>
                          {selectedThreat.evidence.template && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Template:</span>
                              <span className="font-mono text-xs">{selectedThreat.evidence.template}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Informações Nuclei */}
                    {(selectedThreat.evidence.templateId || selectedThreat.evidence.url) && (
                      <div className="p-4 bg-muted/50 border rounded-md md:col-span-2">
                        <h5 className="font-medium text-sm text-foreground mb-2">Detalhes Nuclei</h5>
                        <div className="space-y-1 text-sm">
                          {selectedThreat.evidence.templateId && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Template ID:</span>
                              <span className="font-mono text-xs">{selectedThreat.evidence.templateId}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.url && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">URL:</span>
                              <span className="font-mono text-xs break-all">{selectedThreat.evidence.url}</span>
                            </div>
                          )}
                          {selectedThreat.evidence.matcher && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Matcher:</span>
                              <span className="font-mono text-xs">{selectedThreat.evidence.matcher}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* JSON Raw para debug (colapsável) */}
                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                      Ver dados brutos (JSON)
                    </summary>
                    <div className="mt-2 p-4 bg-muted/50 border rounded-md">
                      <pre className="text-xs text-muted-foreground whitespace-pre-wrap">
                        {JSON.stringify(selectedThreat.evidence, null, 2)}
                      </pre>
                    </div>
                  </details>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Status Change Modal */}
      <Dialog open={statusChangeModal.isOpen} onOpenChange={(open) => 
        !open && setStatusChangeModal({
          threat: null,
          isOpen: false,
          newStatus: '',
          justification: '',
          hibernatedUntil: '',
        })
      }>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Alterar Status da Ameaça</DialogTitle>
          </DialogHeader>
          {statusChangeModal.threat && (
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Ameaça:</p>
                <p className="font-medium">{statusChangeModal.threat.title}</p>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">Status atual:</p>
                <Badge className={getStatusColor(statusChangeModal.threat.status)}>
                  {getStatusLabel(statusChangeModal.threat.status)}
                </Badge>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">Novo status:</p>
                <Badge className={getStatusColor(statusChangeModal.newStatus)}>
                  {getStatusLabel(statusChangeModal.newStatus)}
                </Badge>
              </div>

              <div>
                <label className="text-sm font-medium text-foreground">
                  Justificativa *
                </label>
                <textarea
                  className="mt-1 w-full min-h-[80px] px-3 py-2 text-sm border border-input bg-background rounded-md focus:outline-none focus:ring-2 focus:ring-ring"
                  placeholder="Descreva o motivo da mudança de status..."
                  value={statusChangeModal.justification}
                  onChange={(e) => setStatusChangeModal(prev => ({
                    ...prev,
                    justification: e.target.value
                  }))}
                  data-testid="textarea-justification"
                />
              </div>

              {statusChangeModal.newStatus === 'hibernated' && (
                <div>
                  <label className="text-sm font-medium text-foreground">
                    Data limite para reativação *
                  </label>
                  <Input
                    type="datetime-local"
                    className="mt-1"
                    value={statusChangeModal.hibernatedUntil}
                    onChange={(e) => setStatusChangeModal(prev => ({
                      ...prev,
                      hibernatedUntil: e.target.value
                    }))}
                    min={new Date().toISOString().slice(0, 16)}
                    data-testid="input-hibernated-until"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    A ameaça será reativada automaticamente nesta data
                  </p>
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-4">
                <Button
                  variant="outline"
                  onClick={() => setStatusChangeModal({
                    threat: null,
                    isOpen: false,
                    newStatus: '',
                    justification: '',
                    hibernatedUntil: '',
                  })}
                  disabled={changeStatusMutation.isPending}
                  data-testid="button-cancel-status-change"
                >
                  Cancelar
                </Button>
                <Button
                  onClick={handleStatusSubmit}
                  disabled={changeStatusMutation.isPending}
                  data-testid="button-confirm-status-change"
                >
                  {changeStatusMutation.isPending ? "Alterando..." : "Confirmar"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
