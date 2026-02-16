import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Settings as SettingsIcon, Save, Shield, Clock, Globe, Mail, Key, CheckCircle, AlertTriangle, XCircle, Wifi, WifiOff, Loader2, Copy } from "lucide-react";
import { Setting } from "@shared/schema";

interface SettingsForm {
  // System Settings
  systemName: string;
  systemDescription: string;
  systemTimezone: string;
  
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
  const { connected } = useWebSocket();
  
  const [formData, setFormData] = useState<SettingsForm>({
    systemName: 'SamurEye',
    systemDescription: 'Plataforma de Validação de Exposição Adversarial',
    systemTimezone: 'America/Sao_Paulo',
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

  const [emailSettings, setEmailSettings] = useState({
    smtpHost: '',
    smtpPort: 587,
    smtpSecure: false,
    authType: 'password' as 'password' | 'oauth2_gmail' | 'oauth2_microsoft',
    authUser: '',
    authPasswordPlain: '',
    oauth2ClientId: '',
    oauth2ClientSecretPlain: '',
    oauth2RefreshTokenPlain: '',
    oauth2TenantId: '',
    fromEmail: '',
    fromName: 'SamurEye',
  });

  const [testEmail, setTestEmail] = useState('');

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

  const { data: emailSettingsData } = useQuery<{
    smtpHost: string;
    smtpPort: number;
    smtpSecure: boolean;
    authType: 'password' | 'oauth2_gmail' | 'oauth2_microsoft';
    authUser: string | null;
    oauth2ClientId: string | null;
    oauth2TenantId: string | null;
    fromEmail: string;
    fromName: string;
  } | null>({
    queryKey: ["/api/email-settings"],
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

  const saveEmailSettingsMutation = useMutation({
    mutationFn: async (settings: typeof emailSettings) => {
      return await apiRequest('POST', '/api/email-settings', settings);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-settings"] });
      toast({
        title: "Sucesso",
        description: "Configurações de e-mail salvas com sucesso",
      });
    },
    onError: (error) => {
      toast({
        title: "Erro",
        description: "Falha ao salvar configurações de e-mail",
        variant: "destructive",
      });
    },
  });

  const testEmailMutation = useMutation({
    mutationFn: async (email: string) => {
      return await apiRequest('POST', '/api/email-settings/test', { email });
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "E-mail de teste enviado com sucesso",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Erro",
        description: error.message || "Falha ao enviar e-mail de teste",
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

  // Load email settings when data is available
  useEffect(() => {
    if (emailSettingsData && emailSettingsData.smtpHost) {
      setEmailSettings({
        smtpHost: emailSettingsData.smtpHost,
        smtpPort: emailSettingsData.smtpPort,
        smtpSecure: emailSettingsData.smtpSecure,
        authType: emailSettingsData.authType || 'password',
        authUser: emailSettingsData.authUser || '',
        authPasswordPlain: '',
        oauth2ClientId: emailSettingsData.oauth2ClientId || '',
        oauth2ClientSecretPlain: '',
        oauth2RefreshTokenPlain: '',
        oauth2TenantId: emailSettingsData.oauth2TenantId || '',
        fromEmail: emailSettingsData.fromEmail,
        fromName: emailSettingsData.fromName,
      });
    }
  }, [emailSettingsData]);

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

  const handleEmailSettingChange = (key: keyof typeof emailSettings, value: any) => {
    setEmailSettings(prev => ({ ...prev, [key]: value }));
  };

  const handleSaveEmailSettings = async () => {
    if (!emailSettings.smtpHost || !emailSettings.fromEmail) {
      toast({
        title: "Erro",
        description: "Preencha todos os campos obrigatórios",
        variant: "destructive",
      });
      return;
    }
    
    // Validate based on auth type
    if (emailSettings.authType === 'password') {
      if (!emailSettings.authUser || (!emailSettings.authPasswordPlain && !emailSettingsData)) {
        toast({
          title: "Erro",
          description: "Usuário e senha SMTP são obrigatórios",
          variant: "destructive",
        });
        return;
      }
    } else if (emailSettings.authType === 'oauth2_gmail' || emailSettings.authType === 'oauth2_microsoft') {
      if (!emailSettings.oauth2ClientId || (!emailSettings.oauth2ClientSecretPlain && !emailSettingsData) || (!emailSettings.oauth2RefreshTokenPlain && !emailSettingsData)) {
        toast({
          title: "Erro",
          description: "Client ID, Client Secret e Refresh Token são obrigatórios para OAuth2",
          variant: "destructive",
        });
        return;
      }
      if (emailSettings.authType === 'oauth2_microsoft' && !emailSettings.oauth2TenantId && !emailSettingsData) {
        toast({
          title: "Erro",
          description: "Tenant ID é obrigatório para Microsoft 365",
          variant: "destructive",
        });
        return;
      }
    }
    
    await saveEmailSettingsMutation.mutateAsync(emailSettings);
  };

  const handleTestEmail = async () => {
    if (!testEmail) {
      toast({
        title: "Erro",
        description: "Informe um e-mail para teste",
        variant: "destructive",
      });
      return;
    }
    await testEmailMutation.mutateAsync(testEmail);
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
          wsConnected={connected}
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
            <Tabs defaultValue="geral" className="space-y-6">
              <TabsList className="grid w-full grid-cols-6">
                <TabsTrigger value="geral" className="flex items-center gap-2">
                  <SettingsIcon className="h-4 w-4" />
                  Geral
                </TabsTrigger>
                <TabsTrigger value="seguranca" className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Segurança
                </TabsTrigger>
                <TabsTrigger value="ad" className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  AD Security
                </TabsTrigger>
                <TabsTrigger value="notificacoes" className="flex items-center gap-2">
                  <Mail className="h-4 w-4" />
                  Notificações
                </TabsTrigger>
                <TabsTrigger value="smtp" className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  SMTP
                </TabsTrigger>
                <TabsTrigger value="subscricao" className="flex items-center gap-2">
                  <Key className="h-4 w-4" />
                  Subscrição
                </TabsTrigger>
              </TabsList>

              {/* Tab: Geral */}
              <TabsContent value="geral">
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
                      <Label htmlFor="systemTimezone" className="flex items-center space-x-2">
                        <Globe className="h-4 w-4" />
                        <span>Fuso Horário do Sistema</span>
                      </Label>
                      <Select
                        value={formData.systemTimezone}
                        onValueChange={(value) => handleInputChange('systemTimezone', value)}
                      >
                        <SelectTrigger id="systemTimezone" data-testid="select-timezone">
                          <SelectValue placeholder="Selecione o fuso horário" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="America/Sao_Paulo">América/São Paulo (BRT)</SelectItem>
                          <SelectItem value="America/New_York">América/Nova York (EST)</SelectItem>
                          <SelectItem value="America/Chicago">América/Chicago (CST)</SelectItem>
                          <SelectItem value="America/Los_Angeles">América/Los Angeles (PST)</SelectItem>
                          <SelectItem value="Europe/London">Europa/Londres (GMT)</SelectItem>
                          <SelectItem value="Europe/Paris">Europa/Paris (CET)</SelectItem>
                          <SelectItem value="Asia/Tokyo">Ásia/Tóquio (JST)</SelectItem>
                          <SelectItem value="Asia/Shanghai">Ásia/Xangai (CST)</SelectItem>
                          <SelectItem value="Australia/Sydney">Austrália/Sydney (AEDT)</SelectItem>
                          <SelectItem value="UTC">UTC (Tempo Universal)</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-sm text-muted-foreground mt-1">
                        Usado para calcular horários de execução dos agendamentos
                      </p>
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
              </TabsContent>

              {/* Tab: Segurança */}
              <TabsContent value="seguranca">
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
              </TabsContent>

              {/* Tab: AD Security */}
              <TabsContent value="ad">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Clock className="h-5 w-5" />
                      <span>Configurações AD Security</span>
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
              </TabsContent>

              {/* Tab: Notificações */}
              <TabsContent value="notificacoes">
                <Card>
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
              </TabsContent>

              {/* Tab: SMTP */}
              <TabsContent value="smtp">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Mail className="h-5 w-5" />
                      <span>Configurações de E-mail SMTP</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      Configure o servidor SMTP para envio de notificações por e-mail. Estas configurações são globais e afetam todas as políticas de notificação.
                    </p>

                    <Separator />

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="smtpHost">Servidor SMTP</Label>
                        <Input
                          id="smtpHost"
                          placeholder="smtp.gmail.com"
                          value={emailSettings.smtpHost}
                          onChange={(e) => handleEmailSettingChange('smtpHost', e.target.value)}
                          data-testid="input-smtp-host"
                        />
                      </div>

                      <div>
                        <Label htmlFor="smtpPort">Porta</Label>
                        <Input
                          id="smtpPort"
                          type="number"
                          placeholder="587"
                          value={emailSettings.smtpPort}
                          onChange={(e) => handleEmailSettingChange('smtpPort', parseInt(e.target.value))}
                          data-testid="input-smtp-port"
                        />
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="smtpSecure">Conexão Segura (TLS/SSL)</Label>
                        <p className="text-sm text-muted-foreground">
                          Usar conexão criptografada (recomendado)
                        </p>
                      </div>
                      <Switch
                        id="smtpSecure"
                        checked={emailSettings.smtpSecure}
                        onCheckedChange={(checked) => handleEmailSettingChange('smtpSecure', checked)}
                        data-testid="switch-smtp-secure"
                      />
                    </div>

                    <Separator />

                    <div>
                      <Label htmlFor="authType">Tipo de Autenticação</Label>
                      <Select
                        value={emailSettings.authType}
                        onValueChange={(value) => handleEmailSettingChange('authType', value as 'password' | 'oauth2_gmail' | 'oauth2_microsoft')}
                      >
                        <SelectTrigger id="authType" data-testid="select-auth-type">
                          <SelectValue placeholder="Selecione o tipo de autenticação" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="password">Senha Básica (Legacy)</SelectItem>
                          <SelectItem value="oauth2_gmail">OAuth2 - Google Workspace/Gmail</SelectItem>
                          <SelectItem value="oauth2_microsoft">OAuth2 - Microsoft 365</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-sm text-muted-foreground mt-1">
                        OAuth2 é recomendado para Gmail e Microsoft 365 (senha básica será descontinuada em 2025)
                      </p>
                    </div>

                    {emailSettings.authType === 'password' && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="authUser">Usuário SMTP</Label>
                          <Input
                            id="authUser"
                            placeholder="usuario@dominio.com"
                            value={emailSettings.authUser}
                            onChange={(e) => handleEmailSettingChange('authUser', e.target.value)}
                            data-testid="input-auth-user"
                          />
                        </div>

                        <div>
                          <Label htmlFor="authPassword">Senha SMTP</Label>
                          <Input
                            id="authPassword"
                            type="password"
                            placeholder="••••••••"
                            value={emailSettings.authPasswordPlain}
                            onChange={(e) => handleEmailSettingChange('authPasswordPlain', e.target.value)}
                            data-testid="input-auth-password"
                          />
                          <p className="text-sm text-muted-foreground mt-1">
                            Deixe em branco para manter a senha atual
                          </p>
                        </div>
                      </div>
                    )}

                    {(emailSettings.authType === 'oauth2_gmail' || emailSettings.authType === 'oauth2_microsoft') && (
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="oauth2ClientId">Client ID</Label>
                            <Input
                              id="oauth2ClientId"
                              placeholder="seu-client-id.apps.googleusercontent.com"
                              value={emailSettings.oauth2ClientId}
                              onChange={(e) => handleEmailSettingChange('oauth2ClientId', e.target.value)}
                              data-testid="input-oauth2-client-id"
                            />
                          </div>

                          <div>
                            <Label htmlFor="oauth2ClientSecret">Client Secret</Label>
                            <Input
                              id="oauth2ClientSecret"
                              type="password"
                              placeholder="••••••••"
                              value={emailSettings.oauth2ClientSecretPlain}
                              onChange={(e) => handleEmailSettingChange('oauth2ClientSecretPlain', e.target.value)}
                              data-testid="input-oauth2-client-secret"
                            />
                            <p className="text-sm text-muted-foreground mt-1">
                              Deixe em branco para manter o secret atual
                            </p>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <Label htmlFor="oauth2RefreshToken">Refresh Token</Label>
                            <Input
                              id="oauth2RefreshToken"
                              type="password"
                              placeholder="••••••••"
                              value={emailSettings.oauth2RefreshTokenPlain}
                              onChange={(e) => handleEmailSettingChange('oauth2RefreshTokenPlain', e.target.value)}
                              data-testid="input-oauth2-refresh-token"
                            />
                            <p className="text-sm text-muted-foreground mt-1">
                              Deixe em branco para manter o token atual
                            </p>
                          </div>

                          {emailSettings.authType === 'oauth2_microsoft' && (
                            <div>
                              <Label htmlFor="oauth2TenantId">Tenant ID (Microsoft)</Label>
                              <Input
                                id="oauth2TenantId"
                                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                                value={emailSettings.oauth2TenantId}
                                onChange={(e) => handleEmailSettingChange('oauth2TenantId', e.target.value)}
                                data-testid="input-oauth2-tenant-id"
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <Separator />

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="fromEmail">E-mail Remetente</Label>
                        <Input
                          id="fromEmail"
                          type="email"
                          placeholder="notificacoes@empresa.com"
                          value={emailSettings.fromEmail}
                          onChange={(e) => handleEmailSettingChange('fromEmail', e.target.value)}
                          data-testid="input-from-email"
                        />
                      </div>

                      <div>
                        <Label htmlFor="fromName">Nome do Remetente</Label>
                        <Input
                          id="fromName"
                          placeholder="SamurEye Notificações"
                          value={emailSettings.fromName}
                          onChange={(e) => handleEmailSettingChange('fromName', e.target.value)}
                          data-testid="input-from-name"
                        />
                      </div>
                    </div>

                    <Separator />

                    <div className="flex gap-2">
                      <Button
                        onClick={handleSaveEmailSettings}
                        disabled={saveEmailSettingsMutation.isPending}
                        data-testid="button-save-email-settings"
                      >
                        <Save className="mr-2 h-4 w-4" />
                        {saveEmailSettingsMutation.isPending ? 'Salvando...' : 'Salvar Configurações'}
                      </Button>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <Label htmlFor="testEmail">Testar Configuração</Label>
                      <div className="flex gap-2">
                        <Input
                          id="testEmail"
                          type="email"
                          placeholder="seu-email@dominio.com"
                          value={testEmail}
                          onChange={(e) => setTestEmail(e.target.value)}
                          data-testid="input-test-email"
                        />
                        <Button
                          variant="outline"
                          onClick={handleTestEmail}
                          disabled={testEmailMutation.isPending}
                          data-testid="button-test-email"
                        >
                          {testEmailMutation.isPending ? 'Enviando...' : 'Enviar Teste'}
                        </Button>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        Envie um e-mail de teste para verificar se as configurações estão corretas
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Tab: Subscrição */}
              <TabsContent value="subscricao">
                <SubscriptionTab />
              </TabsContent>
            </Tabs>
          )}
        </div>
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Subscription Tab Component
// ═══════════════════════════════════════════════════════════

interface SubscriptionStatus {
  configured: boolean;
  applianceId: string | null;
  status: string;
  tenantName: string | null;
  plan: string | null;
  expiresAt: string | null;
  features: string[];
  lastHeartbeatAt: string | null;
  lastHeartbeatError: string | null;
  consecutiveFailures: number;
  graceDeadline: string | null;
  consoleBaseUrl: string;
  activatedAt: string | null;
  readOnly: boolean;
}

function SubscriptionTab() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [consoleUrlInput, setConsoleUrlInput] = useState('https://api.samureye.com.br');

  const { data: subscription, isLoading } = useQuery<SubscriptionStatus>({
    queryKey: ['/api/subscription/status'],
    refetchInterval: 60_000, // Refresh every minute
  });

  // Sync console URL from server when data loads
  useEffect(() => {
    if (subscription?.consoleBaseUrl) {
      setConsoleUrlInput(subscription.consoleBaseUrl);
    }
  }, [subscription?.consoleBaseUrl]);

  const activateMutation = useMutation({
    mutationFn: async ({ apiKey, consoleUrl }: { apiKey: string; consoleUrl: string }) => {
      const res = await apiRequest('POST', '/api/subscription/activate', { apiKey, consoleUrl });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['/api/subscription/status'] });
      setApiKeyInput('');
      toast({ title: "Sucesso", description: data.message || "Subscrição ativada com sucesso" });
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) return;
      toast({ title: "Erro", description: error.message || "Falha ao ativar subscrição", variant: "destructive" });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest('POST', '/api/subscription/deactivate');
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/subscription/status'] });
      toast({ title: "Sucesso", description: "Subscrição desativada" });
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) return;
      toast({ title: "Erro", description: error.message || "Falha ao desativar", variant: "destructive" });
    },
  });

  const heartbeatMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest('POST', '/api/subscription/heartbeat');
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/subscription/status'] });
      toast({ title: "Sucesso", description: "Heartbeat enviado com sucesso" });
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) return;
      toast({ title: "Erro", description: error.message || "Falha no heartbeat", variant: "destructive" });
    },
  });

  const handleActivate = () => {
    if (!apiKeyInput.trim()) {
      toast({ title: "Erro", description: "Informe a chave de API", variant: "destructive" });
      return;
    }
    if (!consoleUrlInput.trim()) {
      toast({ title: "Erro", description: "Informe a URL da console central", variant: "destructive" });
      return;
    }
    activateMutation.mutate({ apiKey: apiKeyInput, consoleUrl: consoleUrlInput });
  };

  const handleDeactivate = () => {
    if (!confirm('Tem certeza que deseja desativar a subscrição? O appliance perderá a conexão com a console central.')) return;
    deactivateMutation.mutate();
  };

  const getStatusBadge = (status: string) => {
    const map: Record<string, { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline'; icon: any }> = {
      not_configured: { label: 'Não configurada', variant: 'secondary', icon: WifiOff },
      active: { label: 'Ativa', variant: 'default', icon: CheckCircle },
      expired: { label: 'Expirada', variant: 'destructive', icon: XCircle },
      grace_period: { label: 'Período de graça', variant: 'outline', icon: AlertTriangle },
      unreachable: { label: 'Console inacessível', variant: 'destructive', icon: WifiOff },
    };
    const config = map[status] || map.not_configured;
    const Icon = config.icon;
    return (
      <Badge variant={config.variant} className="text-sm py-1 px-3">
        <Icon className="h-3.5 w-3.5 mr-1.5" />
        {config.label}
      </Badge>
    );
  };

  const formatDate = (iso: string | null) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
  };

  const copyApplianceId = () => {
    if (subscription?.applianceId) {
      navigator.clipboard.writeText(subscription.applianceId);
      toast({ title: "Copiado", description: "ID do appliance copiado" });
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  const isConfigured = subscription?.configured;

  return (
    <div className="space-y-6">
      {/* Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Status da Subscrição
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Status</span>
            {getStatusBadge(subscription?.status || 'not_configured')}
          </div>

          {isConfigured && (
            <>
              <Separator />

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">Tenant</span>
                  <p className="font-medium">{subscription?.tenantName || '—'}</p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Plano</span>
                  <p className="font-medium">{subscription?.plan || '—'}</p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Validade</span>
                  <p className="font-medium">{formatDate(subscription?.expiresAt || null)}</p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Ativado em</span>
                  <p className="font-medium">{formatDate(subscription?.activatedAt || null)}</p>
                </div>
              </div>

              <Separator />

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">Último heartbeat</span>
                  <p className="font-medium flex items-center gap-1.5">
                    {subscription?.lastHeartbeatAt ? (
                      <>
                        <Wifi className="h-3.5 w-3.5 text-green-500" />
                        {formatDate(subscription.lastHeartbeatAt)}
                      </>
                    ) : '—'}
                  </p>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Falhas consecutivas</span>
                  <p className="font-medium">
                    {subscription?.consecutiveFailures || 0}
                    {subscription?.graceDeadline && (
                      <span className="text-xs text-muted-foreground ml-2">
                        (graça até {formatDate(subscription.graceDeadline)})
                      </span>
                    )}
                  </p>
                </div>
              </div>

              {subscription?.lastHeartbeatError && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{subscription.lastHeartbeatError}</AlertDescription>
                </Alert>
              )}

              {subscription?.readOnly && (
                <Alert variant="destructive">
                  <XCircle className="h-4 w-4" />
                  <AlertDescription>
                    O SamurEye está em modo somente-leitura. Atualize sua subscrição na console central para restaurar o acesso completo.
                  </AlertDescription>
                </Alert>
              )}

              <Separator />

              <div>
                <span className="text-sm text-muted-foreground">Appliance ID</span>
                <div className="flex items-center gap-2 mt-1">
                  <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                    {subscription?.applianceId}
                  </code>
                  <Button variant="ghost" size="sm" onClick={copyApplianceId} data-testid="btn-copy-appliance-id">
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => heartbeatMutation.mutate()}
                  disabled={heartbeatMutation.isPending}
                  data-testid="btn-force-heartbeat"
                >
                  {heartbeatMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Wifi className="h-4 w-4 mr-2" />}
                  Testar Conexão
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleDeactivate}
                  disabled={deactivateMutation.isPending}
                  data-testid="btn-deactivate-subscription"
                >
                  Desativar Subscrição
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Activation Card (shown when not configured) */}
      {!isConfigured && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Ativar Subscrição
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Insira a chave de API fornecida pela console central SamurEye para conectar este appliance.
              A chave habilita a comunicação com a plataforma de gestão centralizada.
            </p>

            <div>
              <Label htmlFor="consoleUrl">URL da Console Central</Label>
              <Input
                id="consoleUrl"
                type="url"
                placeholder="https://api.samureye.com.br"
                value={consoleUrlInput}
                onChange={(e) => setConsoleUrlInput(e.target.value)}
                data-testid="input-console-url"
              />
              <p className="text-xs text-muted-foreground mt-1">
                URL base da API da console central (fornecida pelo administrador)
              </p>
            </div>

            <div>
              <Label htmlFor="apiKey">Chave de API</Label>
              <Input
                id="apiKey"
                type="password"
                placeholder="se-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                value={apiKeyInput}
                onChange={(e) => setApiKeyInput(e.target.value)}
                data-testid="input-api-key"
              />
            </div>

            <Button
              onClick={handleActivate}
              disabled={activateMutation.isPending || !apiKeyInput.trim() || !consoleUrlInput.trim()}
              data-testid="btn-activate-subscription"
            >
              {activateMutation.isPending ? (
                <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Ativando...</>
              ) : (
                <><Key className="h-4 w-4 mr-2" /> Ativar Subscrição</>
              )}
            </Button>

            {subscription?.applianceId && (
              <div>
                <span className="text-sm text-muted-foreground">Appliance ID</span>
                <div className="flex items-center gap-2 mt-1">
                  <code className="text-xs bg-muted px-2 py-1 rounded font-mono">
                    {subscription.applianceId}
                  </code>
                  <Button variant="ghost" size="sm" onClick={copyApplianceId} data-testid="btn-copy-appliance-id-2">
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
