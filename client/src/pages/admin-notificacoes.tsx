// client/src/pages/admin-notificacoes.tsx
import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { AdminBreadcrumb } from "@/components/admin/admin-breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
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
import { Bell, Plus, Trash2, Edit, X, Save, Mail } from "lucide-react";
import type { NotificationPolicy, Setting } from "@shared/schema";

interface AlertsForm {
  enableEmailAlerts: boolean;
  alertEmail: string;
  criticalThreatAlert: boolean;
  jobFailureAlert: boolean;
}

export default function AdminNotificacoes() {
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  // ── Alertas Globais ───────────────────────────────────────
  const [alertsForm, setAlertsForm] = useState<AlertsForm>({
    enableEmailAlerts: false,
    alertEmail: "",
    criticalThreatAlert: true,
    jobFailureAlert: true,
  });

  const { data: settings = [] } = useQuery<Setting[]>({
    queryKey: ["/api/settings"],
    enabled: currentUser?.role === "global_administrator",
  });

  const updateSettingMutation = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: any }) =>
      apiRequest("PUT", "/api/settings", { key, value }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings"] });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Não autorizado",
          description: "Você foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => { window.location.href = "/api/login"; }, 500);
        return;
      }
      toast({ title: "Erro", description: "Falha ao atualizar configuração", variant: "destructive" });
    },
  });

  useEffect(() => {
    if (settings.length > 0) {
      setAlertsForm((prev) => {
        const next = { ...prev };
        settings.forEach((s) => {
          if (s.key in next) (next as any)[s.key] = s.value;
        });
        return next;
      });
    }
  }, [settings]);

  const handleAlertChange = (key: keyof AlertsForm, value: any) => {
    setAlertsForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleSaveAlerts = async () => {
    const updates = Object.entries(alertsForm).map(([key, value]) => ({ key, value }));
    try {
      await Promise.all(updates.map((u) => updateSettingMutation.mutateAsync(u)));
      toast({ title: "Sucesso", description: "Alertas globais salvos com sucesso" });
    } catch {
      // errors handled in mutation
    }
  };

  // ── Políticas de Notificação ──────────────────────────────
  const [isCreating, setIsCreating] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<NotificationPolicy | null>(null);
  const [deletePolicyId, setDeletePolicyId] = useState<string | null>(null);
  const [policyForm, setPolicyForm] = useState({
    name: "",
    enabled: true,
    emailAddresses: "",
    severities: { low: false, medium: false, high: false, critical: false },
    statusTriggers: {
      open: false,
      investigating: false,
      mitigated: false,
      hibernated: false,
      accepted_risk: false,
    },
  });

  const { data: policies = [], isLoading: policiesLoading } = useQuery<NotificationPolicy[]>({
    queryKey: ["/api/notification-policies"],
  });

  const createPolicyMutation = useMutation({
    mutationFn: async (data: any) => apiRequest("POST", "/api/notification-policies", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-policies"] });
      toast({ title: "Sucesso", description: "Política criada com sucesso" });
      resetPolicyForm();
    },
    onError: (error: any) => {
      toast({ title: "Erro", description: error.message || "Falha ao criar política", variant: "destructive" });
    },
  });

  const updatePolicyMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: any }) =>
      apiRequest("PATCH", `/api/notification-policies/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-policies"] });
      toast({ title: "Sucesso", description: "Política atualizada com sucesso" });
      resetPolicyForm();
    },
    onError: (error: any) => {
      toast({ title: "Erro", description: error.message || "Falha ao atualizar política", variant: "destructive" });
    },
  });

  const deletePolicyMutation = useMutation({
    mutationFn: async (id: string) =>
      apiRequest("DELETE", `/api/notification-policies/${id}`, undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-policies"] });
      toast({ title: "Sucesso", description: "Política excluída com sucesso" });
    },
    onError: (error: any) => {
      toast({ title: "Erro", description: error.message || "Falha ao excluir política", variant: "destructive" });
    },
  });

  const toggleEnabledMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiRequest("PATCH", `/api/notification-policies/${id}`, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notification-policies"] });
    },
    onError: (error: any) => {
      toast({ title: "Erro", description: error.message || "Falha ao atualizar política", variant: "destructive" });
    },
  });

  const resetPolicyForm = () => {
    setPolicyForm({
      name: "",
      enabled: true,
      emailAddresses: "",
      severities: { low: false, medium: false, high: false, critical: false },
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

  const handleEditPolicy = (policy: NotificationPolicy) => {
    setEditingPolicy(policy);
    setIsCreating(true);
    setPolicyForm({
      name: policy.name,
      enabled: policy.enabled,
      emailAddresses: policy.emailAddresses.join(", "),
      severities: {
        low: policy.severities.includes("low"),
        medium: policy.severities.includes("medium"),
        high: policy.severities.includes("high"),
        critical: policy.severities.includes("critical"),
      },
      statusTriggers: {
        open: policy.statuses.includes("open"),
        investigating: policy.statuses.includes("investigating"),
        mitigated: policy.statuses.includes("mitigated"),
        hibernated: policy.statuses.includes("hibernated"),
        accepted_risk: policy.statuses.includes("accepted_risk"),
      },
    });
  };

  const handleSubmitPolicy = async () => {
    if (!policyForm.name.trim()) {
      toast({ title: "Erro", description: "Nome da política é obrigatório", variant: "destructive" });
      return;
    }
    const emailList = policyForm.emailAddresses
      .split(",")
      .map((e) => e.trim())
      .filter((e) => e.length > 0);
    if (emailList.length === 0) {
      toast({ title: "Erro", description: "Informe pelo menos um e-mail de destino", variant: "destructive" });
      return;
    }
    const selectedSeverities = Object.entries(policyForm.severities)
      .filter(([, checked]) => checked)
      .map(([s]) => s);
    if (selectedSeverities.length === 0) {
      toast({ title: "Erro", description: "Selecione pelo menos um nível de severidade", variant: "destructive" });
      return;
    }
    const selectedStatuses = Object.entries(policyForm.statusTriggers)
      .filter(([, checked]) => checked)
      .map(([s]) => s);
    if (selectedStatuses.length === 0) {
      toast({ title: "Erro", description: "Selecione pelo menos um status de gatilho", variant: "destructive" });
      return;
    }
    const payload = {
      name: policyForm.name.trim(),
      enabled: policyForm.enabled,
      emailAddresses: emailList,
      severities: selectedSeverities,
      statuses: selectedStatuses,
    };
    if (editingPolicy) {
      await updatePolicyMutation.mutateAsync({ id: editingPolicy.id, data: payload });
    } else {
      await createPolicyMutation.mutateAsync(payload);
    }
  };

  const severityLabels: Record<string, string> = {
    low: "Baixa",
    medium: "Média",
    high: "Alta",
    critical: "Crítica",
  };

  const statusLabels: Record<string, string> = {
    open: "Aberto",
    investigating: "Investigando",
    mitigated: "Mitigado",
    hibernated: "Hibernado",
    accepted_risk: "Risco Aceito",
  };

  if (currentUser?.role !== "global_administrator") return null;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Notificações"
          subtitle="Alertas globais e políticas de notificação por e-mail"
          wsConnected={connected}
        />
        <div className="p-6 space-y-8">
          <AdminBreadcrumb page="Notificações" />

          {/* ── Alertas Globais ── */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Alertas Globais
            </p>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Mail className="h-5 w-5" />
                  <span>Configurações de Alerta</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="enableEmailAlerts">Alertas por Email</Label>
                    <p className="text-sm text-muted-foreground">
                      Ativar notificações por email para eventos importantes
                    </p>
                  </div>
                  <Switch
                    id="enableEmailAlerts"
                    checked={alertsForm.enableEmailAlerts}
                    onCheckedChange={(checked) => handleAlertChange("enableEmailAlerts", checked)}
                    data-testid="switch-email-alerts"
                  />
                </div>

                {alertsForm.enableEmailAlerts && (
                  <>
                    <Separator />
                    <div>
                      <Label htmlFor="alertEmail">Email para Alertas</Label>
                      <Input
                        id="alertEmail"
                        type="email"
                        placeholder="admin@empresa.com"
                        value={alertsForm.alertEmail}
                        onChange={(e) => handleAlertChange("alertEmail", e.target.value)}
                        data-testid="input-alert-email"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="criticalThreatAlert">Alertas de Ameaças Críticas</Label>
                        <p className="text-sm text-muted-foreground">
                          Receber email quando ameaças críticas forem detectadas
                        </p>
                      </div>
                      <Switch
                        id="criticalThreatAlert"
                        checked={alertsForm.criticalThreatAlert}
                        onCheckedChange={(checked) =>
                          handleAlertChange("criticalThreatAlert", checked)
                        }
                        data-testid="switch-critical-threat-alert"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="jobFailureAlert">Alertas de Falha em Jobs</Label>
                        <p className="text-sm text-muted-foreground">
                          Receber email quando jobs falharem
                        </p>
                      </div>
                      <Switch
                        id="jobFailureAlert"
                        checked={alertsForm.jobFailureAlert}
                        onCheckedChange={(checked) =>
                          handleAlertChange("jobFailureAlert", checked)
                        }
                        data-testid="switch-job-failure-alert"
                      />
                    </div>
                  </>
                )}

                <div className="flex justify-end pt-2">
                  <Button
                    onClick={handleSaveAlerts}
                    disabled={updateSettingMutation.isPending}
                    data-testid="button-save-alerts"
                  >
                    <Save className="mr-2 h-4 w-4" />
                    {updateSettingMutation.isPending ? "Salvando..." : "Salvar Alertas Globais"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* ── Políticas de Notificação ── */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Políticas de Notificação
              </p>
              {!isCreating && (
                <Button onClick={() => setIsCreating(true)} data-testid="button-create-policy">
                  <Plus className="mr-2 h-4 w-4" />
                  Nova Política
                </Button>
              )}
            </div>

            {isCreating && (
              <Card className="mb-4">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle>{editingPolicy ? "Editar Política" : "Nova Política"}</CardTitle>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={resetPolicyForm}
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
                      value={policyForm.name}
                      onChange={(e) => setPolicyForm((p) => ({ ...p, name: e.target.value }))}
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
                      checked={policyForm.enabled}
                      onCheckedChange={(checked) =>
                        setPolicyForm((p) => ({ ...p, enabled: checked }))
                      }
                      data-testid="switch-policy-enabled"
                    />
                  </div>

                  <Separator />

                  <div>
                    <Label htmlFor="emailAddresses">E-mails de Destino</Label>
                    <Input
                      id="emailAddresses"
                      placeholder="email1@empresa.com, email2@empresa.com"
                      value={policyForm.emailAddresses}
                      onChange={(e) =>
                        setPolicyForm((p) => ({ ...p, emailAddresses: e.target.value }))
                      }
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
                            checked={
                              policyForm.severities[key as keyof typeof policyForm.severities]
                            }
                            onCheckedChange={(checked) =>
                              setPolicyForm((p) => ({
                                ...p,
                                severities: { ...p.severities, [key]: !!checked },
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
                            checked={
                              policyForm.statusTriggers[
                                key as keyof typeof policyForm.statusTriggers
                              ]
                            }
                            onCheckedChange={(checked) =>
                              setPolicyForm((p) => ({
                                ...p,
                                statusTriggers: { ...p.statusTriggers, [key]: !!checked },
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
                      onClick={handleSubmitPolicy}
                      disabled={createPolicyMutation.isPending || updatePolicyMutation.isPending}
                      data-testid="button-save-policy"
                    >
                      {createPolicyMutation.isPending || updatePolicyMutation.isPending
                        ? "Salvando..."
                        : editingPolicy
                        ? "Atualizar Política"
                        : "Criar Política"}
                    </Button>
                    <Button variant="outline" onClick={resetPolicyForm} data-testid="button-cancel-policy">
                      Cancelar
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            <div className="space-y-4">
              {policiesLoading && (
                <div className="text-center py-8 text-muted-foreground">
                  Carregando políticas...
                </div>
              )}

              {!policiesLoading && policies.length === 0 && (
                <Card>
                  <CardContent className="py-8 text-center">
                    <Bell className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-muted-foreground">Nenhuma política configurada ainda.</p>
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
                        <Badge
                          variant={policy.enabled ? "default" : "secondary"}
                          data-testid={`badge-status-${policy.id}`}
                        >
                          {policy.enabled ? "Ativa" : "Inativa"}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={policy.enabled}
                          onCheckedChange={() =>
                            toggleEnabledMutation.mutate({ id: policy.id, enabled: !policy.enabled })
                          }
                          disabled={toggleEnabledMutation.isPending}
                          data-testid={`switch-enabled-${policy.id}`}
                        />
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => handleEditPolicy(policy)}
                          data-testid={`button-edit-${policy.id}`}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() => setDeletePolicyId(policy.id)}
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
                            <Badge
                              key={idx}
                              variant="outline"
                              data-testid={`badge-email-${policy.id}-${idx}`}
                            >
                              {email}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <Label className="text-sm font-medium">Severidades:</Label>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {policy.severities.map((s) => (
                            <Badge
                              key={s}
                              variant="secondary"
                              data-testid={`badge-severity-${policy.id}-${s}`}
                            >
                              {severityLabels[s]}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <Label className="text-sm font-medium">Gatilhos de Status:</Label>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {policy.statuses.map((s: string) => (
                            <Badge
                              key={s}
                              variant="secondary"
                              data-testid={`badge-status-trigger-${policy.id}-${s}`}
                            >
                              {statusLabels[s]}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </main>

      <AlertDialog
        open={!!deletePolicyId}
        onOpenChange={(open) => !open && setDeletePolicyId(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Excluir Política</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja excluir esta política de notificação? Esta ação não pode ser
              desfeita.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (deletePolicyId) {
                  deletePolicyMutation.mutate(deletePolicyId);
                  setDeletePolicyId(null);
                }
              }}
            >
              Sim, Excluir
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
