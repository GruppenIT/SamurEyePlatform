import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { queryClient, apiRequest } from '@/lib/queryClient';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { Bell, Plus, Trash2, Edit, X } from 'lucide-react';
import type { NotificationPolicy } from '@shared/schema';

export default function NotificationPolicies() {
  const { toast } = useToast();
  const [isCreating, setIsCreating] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<NotificationPolicy | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    enabled: true,
    emailAddresses: '',
    severities: {
      low: false,
      medium: false,
      high: false,
      critical: false,
    },
    statusTriggers: {
      open: false,
      investigating: false,
      mitigated: false,
      hibernated: false,
      accepted_risk: false,
    },
  });

  // Queries
  const { data: policies = [], isLoading } = useQuery<NotificationPolicy[]>({
    queryKey: ['/api/notification-policies'],
  });

  // Mutations
  const createPolicyMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest('POST', '/api/notification-policies', data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notification-policies'] });
      toast({
        title: "Sucesso",
        description: "Política criada com sucesso",
      });
      resetForm();
    },
    onError: (error: any) => {
      toast({
        title: "Erro",
        description: error.message || "Falha ao criar política",
        variant: "destructive",
      });
    },
  });

  const updatePolicyMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) => {
      return await apiRequest('PATCH', `/api/notification-policies/${id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notification-policies'] });
      toast({
        title: "Sucesso",
        description: "Política atualizada com sucesso",
      });
      resetForm();
    },
    onError: (error: any) => {
      toast({
        title: "Erro",
        description: error.message || "Falha ao atualizar política",
        variant: "destructive",
      });
    },
  });

  const deletePolicyMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest('DELETE', `/api/notification-policies/${id}`, undefined);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notification-policies'] });
      toast({
        title: "Sucesso",
        description: "Política excluída com sucesso",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Erro",
        description: error.message || "Falha ao excluir política",
        variant: "destructive",
      });
    },
  });

  const toggleEnabledMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      return await apiRequest('PATCH', `/api/notification-policies/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notification-policies'] });
    },
    onError: (error: any) => {
      toast({
        title: "Erro",
        description: error.message || "Falha ao atualizar política",
        variant: "destructive",
      });
    },
  });

  // Handlers
  const resetForm = () => {
    setFormData({
      name: '',
      enabled: true,
      emailAddresses: '',
      severities: {
        low: false,
        medium: false,
        high: false,
        critical: false,
      },
      statusTriggers: {
        open: false,
        investigating: false,
        mitigated: false,
        hibernated: false,
        accepted_risk: false,
      },
    });
    setIsCreating(false);
    setEditingPolicy(null);
  };

  const handleEdit = (policy: NotificationPolicy) => {
    setEditingPolicy(policy);
    setIsCreating(true);
    setFormData({
      name: policy.name,
      enabled: policy.enabled,
      emailAddresses: policy.emailAddresses.join(', '),
      severities: {
        low: policy.severities.includes('low'),
        medium: policy.severities.includes('medium'),
        high: policy.severities.includes('high'),
        critical: policy.severities.includes('critical'),
      },
      statusTriggers: {
        open: policy.statuses.includes('open'),
        investigating: policy.statuses.includes('investigating'),
        mitigated: policy.statuses.includes('mitigated'),
        hibernated: policy.statuses.includes('hibernated'),
        accepted_risk: policy.statuses.includes('accepted_risk'),
      },
    });
  };

  const handleSubmit = async () => {
    // Validation
    if (!formData.name.trim()) {
      toast({
        title: "Erro",
        description: "Nome da política é obrigatório",
        variant: "destructive",
      });
      return;
    }

    const emailList = formData.emailAddresses
      .split(',')
      .map(e => e.trim())
      .filter(e => e.length > 0);

    if (emailList.length === 0) {
      toast({
        title: "Erro",
        description: "Informe pelo menos um e-mail de destino",
        variant: "destructive",
      });
      return;
    }

    const selectedSeverities = Object.entries(formData.severities)
      .filter(([_, checked]) => checked)
      .map(([severity]) => severity);

    if (selectedSeverities.length === 0) {
      toast({
        title: "Erro",
        description: "Selecione pelo menos um nível de severidade",
        variant: "destructive",
      });
      return;
    }

    const selectedStatusTriggers = Object.entries(formData.statusTriggers)
      .filter(([_, checked]) => checked)
      .map(([status]) => status);

    if (selectedStatusTriggers.length === 0) {
      toast({
        title: "Erro",
        description: "Selecione pelo menos um status de gatilho",
        variant: "destructive",
      });
      return;
    }

    const policyData = {
      name: formData.name.trim(),
      enabled: formData.enabled,
      emailAddresses: emailList,
      severities: selectedSeverities,
      statuses: selectedStatusTriggers,
    };

    if (editingPolicy) {
      await updatePolicyMutation.mutateAsync({ id: editingPolicy.id, data: policyData });
    } else {
      await createPolicyMutation.mutateAsync(policyData);
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Tem certeza que deseja excluir esta política?')) {
      await deletePolicyMutation.mutateAsync(id);
    }
  };

  const handleToggleEnabled = async (id: string, currentEnabled: boolean) => {
    await toggleEnabledMutation.mutateAsync({ id, enabled: !currentEnabled });
  };

  const severityLabels: Record<string, string> = {
    low: 'Baixa',
    medium: 'Média',
    high: 'Alta',
    critical: 'Crítica',
  };

  const statusLabels: Record<string, string> = {
    open: 'Aberto',
    investigating: 'Investigando',
    mitigated: 'Mitigado',
    hibernated: 'Hibernado',
    accepted_risk: 'Risco Aceito',
  };

  return (
    <div className="min-h-screen bg-background">
      <main className="container mx-auto py-6 px-4">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center space-x-2">
              <Bell className="h-8 w-8" />
              <span>Políticas de Notificação</span>
            </h1>
            <p className="text-muted-foreground mt-2">
              Configure quando e para quem enviar notificações por e-mail
            </p>
          </div>
          {!isCreating && (
            <Button
              onClick={() => setIsCreating(true)}
              data-testid="button-create-policy"
            >
              <Plus className="mr-2 h-4 w-4" />
              Nova Política
            </Button>
          )}
        </div>

        {isCreating && (
          <Card className="mb-6">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>
                  {editingPolicy ? 'Editar Política' : 'Nova Política'}
                </CardTitle>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={resetForm}
                  data-testid="button-cancel-form"
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <CardDescription>
                Configure os critérios e destinos para notificações por e-mail
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="policyName">Nome da Política</Label>
                <Input
                  id="policyName"
                  placeholder="Ex: Alertas Críticos para Equipe de Segurança"
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                  data-testid="input-policy-name"
                />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <Label htmlFor="policyEnabled">Política Ativa</Label>
                  <p className="text-sm text-muted-foreground">
                    Desative temporariamente sem excluir
                  </p>
                </div>
                <Switch
                  id="policyEnabled"
                  checked={formData.enabled}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, enabled: checked }))}
                  data-testid="switch-policy-enabled"
                />
              </div>

              <Separator />

              <div>
                <Label htmlFor="emailAddresses">E-mails de Destino</Label>
                <Input
                  id="emailAddresses"
                  placeholder="email1@empresa.com, email2@empresa.com"
                  value={formData.emailAddresses}
                  onChange={(e) => setFormData(prev => ({ ...prev, emailAddresses: e.target.value }))}
                  data-testid="input-email-addresses"
                />
                <p className="text-sm text-muted-foreground mt-1">
                  Separe múltiplos e-mails por vírgula
                </p>
              </div>

              <Separator />

              <div>
                <Label>Níveis de Severidade</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  Notificar quando ameaças com estes níveis forem criadas ou alteradas
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(severityLabels).map(([key, label]) => (
                    <div key={key} className="flex items-center space-x-2">
                      <Checkbox
                        id={`severity-${key}`}
                        checked={formData.severities[key as keyof typeof formData.severities]}
                        onCheckedChange={(checked) => 
                          setFormData(prev => ({
                            ...prev,
                            severities: { ...prev.severities, [key]: !!checked }
                          }))
                        }
                        data-testid={`checkbox-severity-${key}`}
                      />
                      <Label htmlFor={`severity-${key}`} className="cursor-pointer">
                        {label}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>

              <Separator />

              <div>
                <Label>Gatilhos de Status</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  Notificar quando o status de uma ameaça mudar para
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {Object.entries(statusLabels).map(([key, label]) => (
                    <div key={key} className="flex items-center space-x-2">
                      <Checkbox
                        id={`status-${key}`}
                        checked={formData.statusTriggers[key as keyof typeof formData.statusTriggers]}
                        onCheckedChange={(checked) => 
                          setFormData(prev => ({
                            ...prev,
                            statusTriggers: { ...prev.statusTriggers, [key]: !!checked }
                          }))
                        }
                        data-testid={`checkbox-status-${key}`}
                      />
                      <Label htmlFor={`status-${key}`} className="cursor-pointer">
                        {label}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>

              <Separator />

              <div className="flex gap-2">
                <Button
                  onClick={handleSubmit}
                  disabled={createPolicyMutation.isPending || updatePolicyMutation.isPending}
                  data-testid="button-save-policy"
                >
                  {createPolicyMutation.isPending || updatePolicyMutation.isPending
                    ? 'Salvando...'
                    : editingPolicy
                    ? 'Atualizar Política'
                    : 'Criar Política'}
                </Button>
                <Button variant="outline" onClick={resetForm} data-testid="button-cancel-policy">
                  Cancelar
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="space-y-4">
          {isLoading && (
            <div className="text-center py-8 text-muted-foreground">
              Carregando políticas...
            </div>
          )}

          {!isLoading && policies.length === 0 && (
            <Card>
              <CardContent className="py-8 text-center">
                <Bell className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">
                  Nenhuma política configurada ainda.
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  Crie sua primeira política para começar a receber notificações.
                </p>
              </CardContent>
            </Card>
          )}

          {policies.map((policy) => (
            <Card key={policy.id} data-testid={`card-policy-${policy.id}`}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <CardTitle>{policy.name}</CardTitle>
                    <Badge variant={policy.enabled ? 'default' : 'secondary'} data-testid={`badge-status-${policy.id}`}>
                      {policy.enabled ? 'Ativa' : 'Inativa'}
                    </Badge>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={() => handleToggleEnabled(policy.id, policy.enabled)}
                      disabled={toggleEnabledMutation.isPending}
                      data-testid={`switch-enabled-${policy.id}`}
                    />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => handleEdit(policy)}
                      data-testid={`button-edit-${policy.id}`}
                    >
                      <Edit className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() => handleDelete(policy.id)}
                      disabled={deletePolicyMutation.isPending}
                      data-testid={`button-delete-${policy.id}`}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium">E-mails de Destino:</Label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {policy.emailAddresses.map((email, idx) => (
                        <Badge key={idx} variant="outline" data-testid={`badge-email-${policy.id}-${idx}`}>
                          {email}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div>
                    <Label className="text-sm font-medium">Severidades:</Label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {policy.severities.map((severity) => (
                        <Badge key={severity} variant="secondary" data-testid={`badge-severity-${policy.id}-${severity}`}>
                          {severityLabels[severity]}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div>
                    <Label className="text-sm font-medium">Gatilhos de Status:</Label>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {policy.statuses.map((status: string) => (
                        <Badge key={status} variant="secondary" data-testid={`badge-status-trigger-${policy.id}-${status}`}>
                          {statusLabels[status]}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </main>
    </div>
  );
}
