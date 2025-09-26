import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import ScheduleForm from "@/components/forms/schedule-form";
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
import { Switch } from "@/components/ui/switch";
import { Plus, Search, Edit, Trash2, Clock, Play, Pause } from "lucide-react";
import { Schedule } from "@shared/schema";
import { ScheduleFormData } from "@/types";

export default function Schedules() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingSchedule, setEditingSchedule] = useState<Schedule | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: schedules = [], isLoading } = useQuery<Schedule[]>({
    queryKey: ["/api/schedules"],
  });

  const createScheduleMutation = useMutation({
    mutationFn: async (data: ScheduleFormData) => {
      return await apiRequest('POST', '/api/schedules', data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Agendamento criado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/schedules"] });
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
        description: "Falha ao criar agendamento",
        variant: "destructive",
      });
    },
  });

  const updateScheduleMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<Schedule> }) => {
      return await apiRequest('PATCH', `/api/schedules/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Agendamento atualizado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/schedules"] });
      setEditingSchedule(null);
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
        description: "Falha ao atualizar agendamento",
        variant: "destructive",
      });
    },
  });

  const deleteScheduleMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest('DELETE', `/api/schedules/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Agendamento excluído com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/schedules"] });
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
        description: "Falha ao excluir agendamento",
        variant: "destructive",
      });
    },
  });

  const filteredSchedules = schedules.filter(schedule =>
    schedule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    schedule.kind.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleCreateSchedule = (data: ScheduleFormData) => {
    createScheduleMutation.mutate(data);
  };

  const handleUpdateSchedule = (data: ScheduleFormData) => {
    if (editingSchedule) {
      updateScheduleMutation.mutate({ id: editingSchedule.id, data });
    }
  };

  const handleDeleteSchedule = (id: string) => {
    if (confirm('Tem certeza que deseja excluir este agendamento?')) {
      deleteScheduleMutation.mutate(id);
    }
  };

  const handleToggleEnabled = (schedule: Schedule) => {
    updateScheduleMutation.mutate({
      id: schedule.id,
      data: { enabled: !schedule.enabled }
    });
  };

  const getScheduleKindLabel = (kind: string) => {
    switch (kind) {
      case 'on_demand':
        return 'Sob Demanda';
      case 'once':
        return 'Único';
      case 'recurring':
        return 'Recorrente';
      default:
        return kind;
    }
  };

  const getScheduleKindBadgeColor = (kind: string) => {
    switch (kind) {
      case 'on_demand':
        return 'bg-muted text-muted-foreground';
      case 'once':
        return 'bg-accent/20 text-accent';
      case 'recurring':
        return 'bg-primary/20 text-primary';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const formatNextExecution = (schedule: Schedule) => {
    if (!schedule.enabled) return 'Pausado';
    
    if (schedule.kind === 'on_demand') return 'Sob demanda';
    
    if (schedule.kind === 'once' && schedule.onceAt) {
      const date = new Date(schedule.onceAt);
      const now = new Date();
      if (date < now) return 'Expirado';
      return date.toLocaleString('pt-BR');
    }
    
    if (schedule.kind === 'recurring') {
      // Primeiro verificar se usa o novo sistema de recorrência
      if (schedule.recurrenceType && schedule.hour !== null && schedule.hour !== undefined) {
        const hourStr = schedule.hour.toString().padStart(2, '0');
        const minuteStr = (schedule.minute || 0).toString().padStart(2, '0');
        const timeStr = `${hourStr}:${minuteStr}`;
        
        switch (schedule.recurrenceType) {
          case 'daily':
            return `Diário às ${timeStr}`;
            
          case 'weekly':
            if (schedule.dayOfWeek !== null && schedule.dayOfWeek !== undefined) {
              const daysOfWeek = ['Domingo', 'Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado'];
              const dayName = daysOfWeek[schedule.dayOfWeek];
              return `Semanal (${dayName} às ${timeStr})`;
            }
            return `Semanal às ${timeStr}`;
            
          case 'monthly':
            if (schedule.dayOfMonth !== null && schedule.dayOfMonth !== undefined) {
              return `Mensal (dia ${schedule.dayOfMonth} às ${timeStr})`;
            }
            return `Mensal às ${timeStr}`;
            
          default:
            return `Recorrente às ${timeStr}`;
        }
      }
      
      // Fallback para sistema CRON legado
      if (schedule.cronExpression) {
        return `CRON: ${schedule.cronExpression}`;
      }
    }
    
    return 'Não configurado';
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Gestão de Agendamentos"
          subtitle="Configure execuções automáticas e programadas das jornadas"
          actions={
            <Button
              onClick={() => setShowCreateDialog(true)}
              data-testid="button-create-schedule"
            >
              <Plus className="mr-2 h-4 w-4" />
              Novo Agendamento
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
                    placeholder="Buscar agendamentos por nome ou tipo..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-schedules"
                  />
                </div>
                <Badge variant="secondary" data-testid="schedules-count">
                  {filteredSchedules.length} agendamentos
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Schedules Table */}
          <Card>
            <CardHeader>
              <CardTitle>Agendamentos Configurados</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando agendamentos...</p>
                </div>
              ) : filteredSchedules.length === 0 ? (
                <div className="text-center py-8">
                  <Clock className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm ? 'Nenhum agendamento encontrado' : 'Nenhum agendamento configurado'}
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    {searchTerm 
                      ? 'Tente ajustar os termos de busca'
                      : 'Comece criando agendamentos para automatizar execuções'
                    }
                  </p>
                  {!searchTerm && (
                    <Button onClick={() => setShowCreateDialog(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Criar Primeiro Agendamento
                    </Button>
                  )}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Nome</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Próxima Execução</TableHead>
                      <TableHead>Criado em</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredSchedules.map((schedule) => (
                      <TableRow key={schedule.id} data-testid={`schedule-row-${schedule.id}`}>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <Switch
                              checked={schedule.enabled}
                              onCheckedChange={() => handleToggleEnabled(schedule)}
                              disabled={updateScheduleMutation.isPending}
                              data-testid={`switch-enabled-${schedule.id}`}
                            />
                            {schedule.enabled ? (
                              <Play className="h-4 w-4 text-chart-4" />
                            ) : (
                              <Pause className="h-4 w-4 text-muted-foreground" />
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="font-medium">
                          {schedule.name}
                        </TableCell>
                        <TableCell>
                          <Badge className={getScheduleKindBadgeColor(schedule.kind)}>
                            {getScheduleKindLabel(schedule.kind)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground font-mono text-sm">
                          {formatNextExecution(schedule)}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {new Date(schedule.createdAt).toLocaleDateString('pt-BR')}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end space-x-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setEditingSchedule(schedule)}
                              data-testid={`button-edit-${schedule.id}`}
                            >
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeleteSchedule(schedule.id)}
                              className="text-destructive hover:text-destructive"
                              data-testid={`button-delete-${schedule.id}`}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Create Schedule Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Criar Novo Agendamento</DialogTitle>
          </DialogHeader>
          <ScheduleForm
            onSubmit={handleCreateSchedule}
            onCancel={() => setShowCreateDialog(false)}
            isLoading={createScheduleMutation.isPending}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Schedule Dialog */}
      <Dialog open={!!editingSchedule} onOpenChange={() => setEditingSchedule(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Editar Agendamento</DialogTitle>
          </DialogHeader>
          {editingSchedule && (
            <ScheduleForm
              onSubmit={handleUpdateSchedule}
              onCancel={() => setEditingSchedule(null)}
              isLoading={updateScheduleMutation.isPending}
              initialData={{
                journeyId: editingSchedule.journeyId,
                name: editingSchedule.name,
                kind: editingSchedule.kind,
                cronExpression: editingSchedule.cronExpression || '',
                onceAt: editingSchedule.onceAt ? new Date(editingSchedule.onceAt) : undefined,
                enabled: editingSchedule.enabled,
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
