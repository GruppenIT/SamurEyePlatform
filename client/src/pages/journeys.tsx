import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import JourneyForm from "@/components/forms/journey-form";
import ApiSecurityWizard from "@/components/forms/api-security-wizard";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Plus, Search, Edit, Trash2, Play, Route, Search as SearchIcon, Users, Worm, Globe, Eye, Code2, ChevronDown } from "lucide-react";
import { format } from "date-fns";
import { Journey } from "@shared/schema";
import { JourneyFormData } from "@/types";

type EdrDeploymentWithHost = {
  id: string;
  hostId: string;
  journeyId: string;
  jobId: string;
  deploymentTimestamp: string | null;
  detectionTimestamp: string | null;
  deploymentMethod: string;
  detected: boolean | null;
  testDuration: number;
  createdAt: string;
  hostName: string | null;
  hostIps: string[];
  hostOperatingSystem: string | null;
};

function DetectionBadge({ detected }: { detected: boolean | null }) {
  if (detected === true) return <Badge className="bg-green-500/20 text-green-500">Detectado</Badge>;
  if (detected === false) return <Badge className="bg-red-500/20 text-red-500">Nao Detectado</Badge>;
  return <Badge className="bg-muted text-muted-foreground">N/A</Badge>;
}

export default function Journeys() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showApiWizard, setShowApiWizard] = useState(false);
  const [editingJourney, setEditingJourney] = useState<Journey | null>(null);
  const [selectedJourneyId, setSelectedJourneyId] = useState<string | null>(null);

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const { data: journeys = [], isLoading } = useQuery<Journey[]>({
    queryKey: ["/api/journeys"],
  });

  const { data: journeyCredentials = [], isLoading: isLoadingCredentials } = useQuery<Array<{id: string; journeyId: string; credentialId: string; protocol: string; priority: number}>>({
    queryKey: [`/api/journeys/${editingJourney?.id}/credentials`],
    enabled: !!editingJourney,
  });

  const { data: edrDeployments = [], isLoading: isLoadingEdr } = useQuery<EdrDeploymentWithHost[]>({
    queryKey: ["/api/edr-deployments", { journeyId: selectedJourneyId }],
    enabled: !!selectedJourneyId,
  });

  const createJourneyMutation = useMutation({
    mutationFn: async (data: JourneyFormData) => {
      return await apiRequest('POST', '/api/journeys', data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Jornada criada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/journeys"] });
      setShowCreateDialog(false);
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
        description: "Falha ao criar jornada",
        variant: "destructive",
      });
    },
  });

  const updateJourneyMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<JourneyFormData> }) => {
      const { type: _t, createdAt: _c, createdBy: _cb, id: _i, ...editablePayload } = data as any;
      return await apiRequest('PATCH', `/api/journeys/${id}`, editablePayload);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Jornada atualizada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/journeys"] });
      setEditingJourney(null);
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
        description: "Falha ao atualizar jornada",
        variant: "destructive",
      });
    },
  });

  const deleteJourneyMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest('DELETE', `/api/journeys/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Jornada excluída com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/journeys"] });
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
        description: "Falha ao excluir jornada",
        variant: "destructive",
      });
    },
  });

  const executeJourneyMutation = useMutation({
    mutationFn: async (journeyId: string) => {
      return await apiRequest('POST', '/api/jobs/execute', { journeyId });
    },
    onSuccess: () => {
      toast({
        title: "Job Iniciado",
        description: "A jornada foi adicionada à fila de execução",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
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
        description: "Falha ao executar jornada",
        variant: "destructive",
      });
    },
  });

  const filteredJourneys = journeys.filter(journey =>
    journey.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    journey.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (journey.description && journey.description.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const edrTotalHosts = edrDeployments.length;
  const edrDetectedCount = edrDeployments.filter(d => d.detected === true).length;
  const edrDetectionRate = edrTotalHosts > 0 ? Math.round((edrDetectedCount / edrTotalHosts) * 100) : 0;
  const edrAvgDuration = edrTotalHosts > 0
    ? Math.round(edrDeployments.reduce((sum, d) => sum + (d.testDuration || 0), 0) / edrTotalHosts)
    : 0;

  const handleCreateJourney = (data: JourneyFormData) => {
    createJourneyMutation.mutate(data);
  };

  const handleUpdateJourney = (data: JourneyFormData) => {
    if (editingJourney) {
      updateJourneyMutation.mutate({ id: editingJourney.id, data });
    }
  };

  const handleDeleteJourney = (id: string) => {
    if (confirm('Tem certeza que deseja excluir esta jornada?')) {
      deleteJourneyMutation.mutate(id);
    }
  };

  const handleExecuteJourney = (journeyId: string) => {
    executeJourneyMutation.mutate(journeyId);
  };

  const getJourneyIcon = (type: string) => {
    switch (type) {
      case 'attack_surface':
        return SearchIcon;
      case 'ad_security':
        return Users;
      case 'edr_av':
        return Worm;
      case 'web_application':
        return Globe;
      case 'api_security':
        return Code2;
      default:
        return Route;
    }
  };

  const getJourneyTypeLabel = (type: string) => {
    switch (type) {
      case 'attack_surface':
        return 'Attack Surface';
      case 'ad_security':
        return 'AD Security';
      case 'edr_av':
        return 'Teste EDR/AV';
      case 'web_application':
        return 'Web Application';
      case 'api_security':
        return 'API Security';
      default:
        return type;
    }
  };

  const getJourneyTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'attack_surface':
        return 'bg-primary/20 text-primary';
      case 'ad_security':
        return 'bg-accent/20 text-accent';
      case 'edr_av':
        return 'bg-chart-5/20 text-chart-5';
      case 'web_application':
        return 'bg-blue-500/20 text-blue-500';
      case 'api_security':
        return 'bg-emerald-500/20 text-emerald-600';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Gestão de Jornadas"
          subtitle="Configure e execute jornadas de validação de segurança"
          wsConnected={connected}
        />
        
        <div className="p-6 space-y-6">
          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar jornadas por nome, tipo ou descrição..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-journeys"
                  />
                </div>
                <Badge variant="secondary" data-testid="journeys-count">
                  {filteredJourneys.length} jornadas
                </Badge>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button data-testid="button-create-journey">
                      <Plus className="mr-2 h-4 w-4" />
                      Nova Jornada
                      <ChevronDown className="ml-2 h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => setShowCreateDialog(true)}>
                      <Route className="mr-2 h-4 w-4" />
                      Jornada de Segurança
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setShowApiWizard(true)}>
                      <Code2 className="mr-2 h-4 w-4" />
                      Jornada API Security
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardContent>
          </Card>

          {/* Journeys Table */}
          <Card>
            <CardHeader>
              <CardTitle>Jornadas Configuradas</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando jornadas...</p>
                </div>
              ) : filteredJourneys.length === 0 ? (
                <div className="text-center py-8">
                  <Route className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm ? 'Nenhuma jornada encontrada' : 'Nenhuma jornada configurada'}
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    {searchTerm 
                      ? 'Tente ajustar os termos de busca'
                      : 'Comece criando jornadas para automatizar validações de segurança'
                    }
                  </p>
                  {!searchTerm && (
                    <Button onClick={() => setShowCreateDialog(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Criar Primeira Jornada
                    </Button>
                  )}
                </div>
              ) : (
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Nome</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Descrição</TableHead>
                      <TableHead>Criada em</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredJourneys.map((journey) => {
                      const Icon = getJourneyIcon(journey.type);
                      return (
                        <TableRow key={journey.id} data-testid={`journey-row-${journey.id}`}>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <Icon className="h-4 w-4 text-muted-foreground" />
                              <span className="font-medium">{journey.name}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={getJourneyTypeBadgeColor(journey.type)}>
                              {getJourneyTypeLabel(journey.type)}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-xs">
                            <div className="space-y-1">
                              <div className="text-muted-foreground truncate">
                                {journey.description || 'Sem descrição'}
                              </div>
                              {journey.targetSelectionMode === 'by_tag' && journey.selectedTags && journey.selectedTags.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                  {journey.selectedTags.map((tag) => (
                                    <Badge key={tag} variant="outline" className="text-xs">
                                      🏷️ {tag}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {new Date(journey.createdAt).toLocaleDateString('pt-BR')}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end space-x-2">
                              {journey.type === 'edr_av' && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => setSelectedJourneyId(journey.id)}
                                  data-testid={`button-results-${journey.id}`}
                                  title="Ver Resultados EDR"
                                >
                                  <Eye className="h-4 w-4" />
                                </Button>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleExecuteJourney(journey.id)}
                                disabled={executeJourneyMutation.isPending}
                                data-testid={`button-execute-${journey.id}`}
                              >
                                <Play className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setEditingJourney(journey)}
                                data-testid={`button-edit-${journey.id}`}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDeleteJourney(journey.id)}
                                className="text-destructive hover:text-destructive"
                                data-testid={`button-delete-${journey.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Create Journey Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Criar Nova Jornada</DialogTitle>
          </DialogHeader>
          <JourneyForm
            onSubmit={handleCreateJourney}
            onCancel={() => setShowCreateDialog(false)}
            isLoading={createJourneyMutation.isPending}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Journey Dialog */}
      <Dialog open={!!editingJourney} onOpenChange={() => setEditingJourney(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Editar Jornada</DialogTitle>
          </DialogHeader>
          {editingJourney && isLoadingCredentials && (
            <div className="flex items-center justify-center p-8">
              <div className="text-muted-foreground">Carregando credenciais...</div>
            </div>
          )}
          {editingJourney && !isLoadingCredentials && (() => {
            const initialDataPayload = {
              name: editingJourney.name,
              type: editingJourney.type,
              description: editingJourney.description || '',
              params: editingJourney.params,
              targetSelectionMode: editingJourney.targetSelectionMode || 'individual',
              selectedTags: editingJourney.selectedTags || [],
              enableCveDetection: editingJourney.enableCveDetection,
              credentials: journeyCredentials.map(jc => ({
                credentialId: jc.credentialId,
                protocol: jc.protocol as 'wmi' | 'ssh' | 'snmp',
                priority: jc.priority
              }))
            };

            console.group('🔍 [DEBUG] Journeys.tsx - Edit Journey');
            console.log('1. editingJourney:', editingJourney);
            console.log('2. journeyCredentials from query:', journeyCredentials);
            console.log('3. initialData being passed to JourneyForm:', initialDataPayload);
            console.groupEnd();

            return (
              <JourneyForm
                key={editingJourney.id}
                mode="edit"
                onSubmit={handleUpdateJourney}
                onCancel={() => setEditingJourney(null)}
                isLoading={updateJourneyMutation.isPending}
                initialData={initialDataPayload}
              />
            );
          })()}
        </DialogContent>
      </Dialog>

      {/* API Security Wizard */}
      <ApiSecurityWizard open={showApiWizard} onOpenChange={setShowApiWizard} />

      {/* EDR Deployment Results Sheet */}
      <Sheet open={!!selectedJourneyId} onOpenChange={(open) => !open && setSelectedJourneyId(null)}>
        <SheetContent side="right" className="w-[700px] sm:max-w-[700px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Resultados EDR</SheetTitle>
            <SheetDescription>Resultados de validacao EDR/AV por host</SheetDescription>
          </SheetHeader>

          <div className="mt-6 space-y-6">
            {isLoadingEdr ? (
              <div className="flex items-center justify-center py-12">
                <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
              </div>
            ) : edrDeployments.length === 0 ? (
              <div className="text-center py-12">
                <Eye className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-2">Nenhum resultado EDR</h3>
                <p className="text-muted-foreground">
                  Esta jornada ainda nao possui resultados de validacao EDR/AV.
                </p>
              </div>
            ) : (
              <>
                {/* Summary Stats Banner */}
                <div className="grid grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold">{edrTotalHosts}</div>
                      <div className="text-sm text-muted-foreground">Hosts Testados</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold">{edrDetectionRate}%</div>
                      <div className="text-sm text-muted-foreground">Taxa de Deteccao</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <div className="text-2xl font-bold">{edrAvgDuration}s</div>
                      <div className="text-sm text-muted-foreground">Duracao Media</div>
                    </CardContent>
                  </Card>
                </div>

                {/* Per-Host Results Table */}
                <Card>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Host</TableHead>
                          <TableHead>SO</TableHead>
                          <TableHead>Deteccao</TableHead>
                          <TableHead>Metodo</TableHead>
                          <TableHead>Duracao</TableHead>
                          <TableHead>Implantacao</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {edrDeployments.map((dep) => (
                          <TableRow key={dep.id}>
                            <TableCell>
                              <div>
                                <div className="font-medium">{dep.hostName || dep.hostId}</div>
                                {dep.hostIps && dep.hostIps.length > 0 && (
                                  <div className="text-xs text-muted-foreground">{dep.hostIps.join(', ')}</div>
                                )}
                              </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {dep.hostOperatingSystem || '\u2014'}
                            </TableCell>
                            <TableCell>
                              <DetectionBadge detected={dep.detected} />
                            </TableCell>
                            <TableCell className="text-muted-foreground">{dep.deploymentMethod}</TableCell>
                            <TableCell className="text-muted-foreground">{dep.testDuration}s</TableCell>
                            <TableCell className="text-muted-foreground">
                              {dep.deploymentTimestamp ? format(new Date(dep.deploymentTimestamp), 'dd/MM/yyyy HH:mm') : '\u2014'}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
