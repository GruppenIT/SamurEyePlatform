import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import JourneyForm from "@/components/forms/journey-form";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Plus, Search, Edit, Trash2, Play, Route, Search as SearchIcon, Users, Worm, Globe } from "lucide-react";
import { Journey } from "@shared/schema";
import { JourneyFormData } from "@/types";

export default function Journeys() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingJourney, setEditingJourney] = useState<Journey | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: journeys = [], isLoading } = useQuery<Journey[]>({
    queryKey: ["/api/journeys"],
  });

  const { data: journeyCredentials = [], isLoading: isLoadingCredentials } = useQuery<Array<{id: string; journeyId: string; credentialId: string; protocol: string; priority: number}>>({
    queryKey: [`/api/journeys/${editingJourney?.id}/credentials`],
    enabled: !!editingJourney,
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
      return await apiRequest('PATCH', `/api/journeys/${id}`, data);
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
          actions={
            <Button
              onClick={() => setShowCreateDialog(true)}
              data-testid="button-create-journey"
            >
              <Plus className="mr-2 h-4 w-4" />
              Nova Jornada
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
                onSubmit={handleUpdateJourney}
                onCancel={() => setEditingJourney(null)}
                isLoading={updateJourneyMutation.isPending}
                initialData={initialDataPayload}
              />
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}
