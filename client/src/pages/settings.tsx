import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Settings as SettingsIcon, Save, Shield, Clock } from "lucide-react";
import { Setting } from "@shared/schema";

interface SettingsForm {
  // System Settings
  systemName: string;
  systemDescription: string;
  
  // Security Settings
  sessionTimeout: number;
  maxConcurrentJobs: number;
  jobTimeout: number;
  
  // AD Hygiene Thresholds
  adPasswordAgeThreshold: number;
  adInactiveUserThreshold: number;
  
  // Notification Settings
  enableEmailAlerts: boolean;
  alertEmail: string;
  criticalThreatAlert: boolean;
  jobFailureAlert: boolean;
}

export default function Settings() {
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  
  const [formData, setFormData] = useState<SettingsForm>({
    systemName: 'SamurEye',
    systemDescription: 'Plataforma de Validação de Exposição Adversarial',
    sessionTimeout: 3600,
    maxConcurrentJobs: 3,
    jobTimeout: 1800,
    adPasswordAgeThreshold: 90,
    adInactiveUserThreshold: 180,
    enableEmailAlerts: false,
    alertEmail: '',
    criticalThreatAlert: true,
    jobFailureAlert: true,
  });

  // Redirect if not admin
  useEffect(() => {
    if (currentUser && currentUser.role !== 'global_administrator') {
      toast({
        title: "Acesso Negado",
        description: "Você não tem permissão para acessar esta área",
        variant: "destructive",
      });
      window.history.back();
    }
  }, [currentUser, toast]);

  const { data: settings = [], isLoading } = useQuery<Setting[]>({
    queryKey: ["/api/settings"],
    enabled: currentUser?.role === 'global_administrator',
  });

  const updateSettingMutation = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: any }) => {
      return await apiRequest('PUT', '/api/settings', { key, value });
    },
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
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: "Falha ao atualizar configuração",
        variant: "destructive",
      });
    },
  });

  // Load settings into form when data is available
  useEffect(() => {
    if (settings.length > 0) {
      setFormData(prev => {
        const newFormData = { ...prev };
        settings.forEach(setting => {
          if (setting.key in newFormData) {
            (newFormData as any)[setting.key] = setting.value;
          }
        });
        return newFormData;
      });
    }
  }, [settings]); // Remover formData das dependências para evitar loops

  const handleSave = async () => {
    const updates = Object.entries(formData).map(([key, value]) => ({ key, value }));
    
    try {
      await Promise.all(
        updates.map(update => updateSettingMutation.mutateAsync(update))
      );
      
      toast({
        title: "Sucesso",
        description: "Configurações salvas com sucesso",
      });
    } catch (error) {
      // Error handling is done in the mutation
    }
  };

  const handleInputChange = (key: keyof SettingsForm, value: any) => {
    setFormData(prev => ({ ...prev, [key]: value }));
  };

  // Don't render if not admin
  if (currentUser?.role !== 'global_administrator') {
    return null;
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Configurações do Sistema"
          subtitle="Configure parâmetros globais e comportamentos do sistema"
          actions={
            <Button
              onClick={handleSave}
              disabled={updateSettingMutation.isPending}
              data-testid="button-save-settings"
            >
              <Save className="mr-2 h-4 w-4" />
              {updateSettingMutation.isPending ? 'Salvando...' : 'Salvar Alterações'}
            </Button>
          }
        />
        
        <div className="p-6 space-y-6">
          {isLoading ? (
            <div className="text-center py-8">
              <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <p className="text-muted-foreground">Carregando configurações...</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* System Settings */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <SettingsIcon className="h-5 w-5" />
                    <span>Configurações Gerais</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="systemName">Nome do Sistema</Label>
                    <Input
                      id="systemName"
                      value={formData.systemName}
                      onChange={(e) => handleInputChange('systemName', e.target.value)}
                      data-testid="input-system-name"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="systemDescription">Descrição</Label>
                    <Textarea
                      id="systemDescription"
                      value={formData.systemDescription}
                      onChange={(e) => handleInputChange('systemDescription', e.target.value)}
                      data-testid="textarea-system-description"
                    />
                  </div>

                  <div>
                    <Label htmlFor="sessionTimeout">Timeout de Sessão (segundos)</Label>
                    <Input
                      id="sessionTimeout"
                      type="number"
                      value={formData.sessionTimeout}
                      onChange={(e) => handleInputChange('sessionTimeout', parseInt(e.target.value))}
                      data-testid="input-session-timeout"
                    />
                    <p className="text-sm text-muted-foreground mt-1">
                      Tempo para expirar sessões inativas
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Security Settings */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Shield className="h-5 w-5" />
                    <span>Configurações de Segurança</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="maxConcurrentJobs">Máximo de Jobs Concorrentes</Label>
                    <Input
                      id="maxConcurrentJobs"
                      type="number"
                      min="1"
                      max="10"
                      value={formData.maxConcurrentJobs}
                      onChange={(e) => handleInputChange('maxConcurrentJobs', parseInt(e.target.value))}
                      data-testid="input-max-concurrent-jobs"
                    />
                    <p className="text-sm text-muted-foreground mt-1">
                      Limite de jobs executando simultaneamente
                    </p>
                  </div>

                  <div>
                    <Label htmlFor="jobTimeout">Timeout de Jobs (segundos)</Label>
                    <Input
                      id="jobTimeout"
                      type="number"
                      value={formData.jobTimeout}
                      onChange={(e) => handleInputChange('jobTimeout', parseInt(e.target.value))}
                      data-testid="input-job-timeout"
                    />
                    <p className="text-sm text-muted-foreground mt-1">
                      Tempo máximo para execução de um job
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* AD Hygiene Settings */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Clock className="h-5 w-5" />
                    <span>Configurações Higiene AD</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="adPasswordAgeThreshold">Limite Idade da Senha (dias)</Label>
                    <Input
                      id="adPasswordAgeThreshold"
                      type="number"
                      value={formData.adPasswordAgeThreshold}
                      onChange={(e) => handleInputChange('adPasswordAgeThreshold', parseInt(e.target.value))}
                      data-testid="input-ad-password-age"
                    />
                    <p className="text-sm text-muted-foreground mt-1">
                      Alertar sobre senhas não alteradas há X dias
                    </p>
                  </div>

                  <div>
                    <Label htmlFor="adInactiveUserThreshold">Limite Usuário Inativo (dias)</Label>
                    <Input
                      id="adInactiveUserThreshold"
                      type="number"
                      value={formData.adInactiveUserThreshold}
                      onChange={(e) => handleInputChange('adInactiveUserThreshold', parseInt(e.target.value))}
                      data-testid="input-ad-inactive-user"
                    />
                    <p className="text-sm text-muted-foreground mt-1">
                      Alertar sobre usuários sem login há X dias
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Notification Settings */}
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Configurações de Notificação</CardTitle>
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
                      checked={formData.enableEmailAlerts}
                      onCheckedChange={(checked) => handleInputChange('enableEmailAlerts', checked)}
                      data-testid="switch-email-alerts"
                    />
                  </div>

                  {formData.enableEmailAlerts && (
                    <>
                      <Separator />
                      
                      <div>
                        <Label htmlFor="alertEmail">Email para Alertas</Label>
                        <Input
                          id="alertEmail"
                          type="email"
                          placeholder="admin@empresa.com"
                          value={formData.alertEmail}
                          onChange={(e) => handleInputChange('alertEmail', e.target.value)}
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
                          checked={formData.criticalThreatAlert}
                          onCheckedChange={(checked) => handleInputChange('criticalThreatAlert', checked)}
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
                          checked={formData.jobFailureAlert}
                          onCheckedChange={(checked) => handleInputChange('jobFailureAlert', checked)}
                          data-testid="switch-job-failure-alert"
                        />
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
