// client/src/pages/admin-mensageria.tsx
import { useEffect, useRef, useState, KeyboardEvent } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { AdminBreadcrumb } from "@/components/admin/admin-breadcrumb";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Save, Inbox, ServerCog } from "lucide-react";
import { MessagingProviderCard } from "@/components/settings/MessagingProviderCard";
import { MessagingProviderGuide } from "@/components/settings/MessagingProviderGuide";
import { GoogleWorkspaceLogo, MicrosoftLogo } from "@/components/settings/provider-logos";

type MessagingProvider = "google" | "microsoft" | "smtp";

const PROVIDER_TO_AUTH_TYPE: Record<
  MessagingProvider,
  "oauth2_gmail" | "oauth2_microsoft" | "password"
> = {
  google: "oauth2_gmail",
  microsoft: "oauth2_microsoft",
  smtp: "password",
};

const AUTH_TYPE_TO_PROVIDER: Record<
  "oauth2_gmail" | "oauth2_microsoft" | "password",
  MessagingProvider
> = {
  oauth2_gmail: "google",
  oauth2_microsoft: "microsoft",
  password: "smtp",
};

// Google and Microsoft 365 SMTP submission (port 587) use STARTTLS, not implicit TLS,
// so smtpSecure must be false. The backend then sets requireTLS=true to negotiate TLS.
const PROVIDER_DEFAULTS: Record<
  MessagingProvider,
  { smtpHost: string; smtpPort: number; smtpSecure: boolean } | null
> = {
  google: { smtpHost: "smtp.gmail.com", smtpPort: 587, smtpSecure: false },
  microsoft: { smtpHost: "smtp.office365.com", smtpPort: 587, smtpSecure: false },
  smtp: null,
};

const PROVIDER_ORDER: MessagingProvider[] = ["google", "microsoft", "smtp"];

export default function AdminMensageria() {
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const [emailSettings, setEmailSettings] = useState({
    smtpHost: "",
    smtpPort: 587,
    smtpSecure: false,
    authType: "password" as "password" | "oauth2_gmail" | "oauth2_microsoft",
    authUser: "",
    authPasswordPlain: "",
    oauth2ClientId: "",
    oauth2ClientSecretPlain: "",
    oauth2RefreshTokenPlain: "",
    oauth2TenantId: "",
    fromEmail: "",
    fromName: "SamurEye",
  });

  const [testEmail, setTestEmail] = useState("");

  const { data: emailSettingsData } = useQuery<{
    smtpHost: string;
    smtpPort: number;
    smtpSecure: boolean;
    authType: "password" | "oauth2_gmail" | "oauth2_microsoft";
    authUser: string | null;
    oauth2ClientId: string | null;
    oauth2TenantId: string | null;
    fromEmail: string;
    fromName: string;
  } | null>({
    queryKey: ["/api/email-settings"],
    enabled: currentUser?.role === "global_administrator",
  });

  const saveEmailSettingsMutation = useMutation({
    mutationFn: async (settings: typeof emailSettings) =>
      apiRequest("POST", "/api/email-settings", settings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/email-settings"] });
      toast({ title: "Sucesso", description: "Configurações de e-mail salvas com sucesso" });
    },
    onError: () => {
      toast({ title: "Erro", description: "Falha ao salvar configurações de e-mail", variant: "destructive" });
    },
  });

  const testEmailMutation = useMutation({
    mutationFn: async (email: string) =>
      apiRequest("POST", "/api/email-settings/test", { email }),
    onSuccess: () => {
      toast({ title: "Sucesso", description: "E-mail de teste enviado com sucesso" });
    },
    onError: (error: any) => {
      toast({ title: "Erro", description: error.message || "Falha ao enviar e-mail de teste", variant: "destructive" });
    },
  });

  useEffect(() => {
    if (emailSettingsData && emailSettingsData.smtpHost) {
      setEmailSettings({
        smtpHost: emailSettingsData.smtpHost,
        smtpPort: emailSettingsData.smtpPort,
        smtpSecure: emailSettingsData.smtpSecure,
        authType: emailSettingsData.authType || "password",
        authUser: emailSettingsData.authUser || "",
        authPasswordPlain: "",
        oauth2ClientId: emailSettingsData.oauth2ClientId || "",
        oauth2ClientSecretPlain: "",
        oauth2RefreshTokenPlain: "",
        oauth2TenantId: emailSettingsData.oauth2TenantId || "",
        fromEmail: emailSettingsData.fromEmail,
        fromName: emailSettingsData.fromName,
      });
    }
  }, [emailSettingsData]);

  const selectedProvider: MessagingProvider =
    AUTH_TYPE_TO_PROVIDER[emailSettings.authType] ?? "smtp";

  const customSmtpRef = useRef<{ smtpHost: string; smtpPort: number; smtpSecure: boolean }>({
    smtpHost: "",
    smtpPort: 587,
    smtpSecure: false,
  });

  useEffect(() => {
    if (selectedProvider === "smtp") {
      customSmtpRef.current = {
        smtpHost: emailSettings.smtpHost,
        smtpPort: emailSettings.smtpPort,
        smtpSecure: emailSettings.smtpSecure,
      };
    }
  }, [selectedProvider, emailSettings.smtpHost, emailSettings.smtpPort, emailSettings.smtpSecure]);

  const isProviderConfigured = (provider: MessagingProvider): boolean => {
    if (!emailSettingsData) return false;
    if (emailSettingsData.authType !== PROVIDER_TO_AUTH_TYPE[provider]) return false;
    if (provider === "smtp") return Boolean(emailSettingsData.authUser);
    return Boolean(emailSettingsData.oauth2ClientId);
  };

  const handleSelectProvider = (provider: MessagingProvider) => {
    setEmailSettings((prev) => {
      if (provider === "smtp") {
        return {
          ...prev,
          authType: "password",
          smtpHost: customSmtpRef.current.smtpHost,
          smtpPort: customSmtpRef.current.smtpPort,
          smtpSecure: customSmtpRef.current.smtpSecure,
        };
      }
      const defaults = PROVIDER_DEFAULTS[provider]!;
      return {
        ...prev,
        authType: PROVIDER_TO_AUTH_TYPE[provider],
        smtpHost: defaults.smtpHost,
        smtpPort: defaults.smtpPort,
        smtpSecure: defaults.smtpSecure,
      };
    });
  };

  const handleProviderKeyDown =
    (provider: MessagingProvider) => (event: KeyboardEvent<HTMLButtonElement>) => {
      const keys = ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"];
      if (!keys.includes(event.key)) return;
      event.preventDefault();
      const currentIndex = PROVIDER_ORDER.indexOf(provider);
      const delta = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : -1;
      const nextIndex = (currentIndex + delta + PROVIDER_ORDER.length) % PROVIDER_ORDER.length;
      const nextProvider = PROVIDER_ORDER[nextIndex];
      handleSelectProvider(nextProvider);
      // TODO: refactor to a ref map if MessagingProviderCard ever renders multiple times per page or the data-testid naming changes
      const nextCard = document.querySelector<HTMLButtonElement>(
        `[data-testid="card-messaging-provider-${nextProvider}"]`,
      );
      nextCard?.focus();
    };

  const handleEmailSettingChange = (key: keyof typeof emailSettings, value: any) => {
    setEmailSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSaveEmailSettings = async () => {
    if (!emailSettings.smtpHost || !emailSettings.fromEmail) {
      toast({ title: "Erro", description: "Preencha todos os campos obrigatórios", variant: "destructive" });
      return;
    }
    if (emailSettings.authType === "password") {
      if (!emailSettings.authUser || (!emailSettings.authPasswordPlain && !emailSettingsData)) {
        toast({ title: "Erro", description: "Usuário e senha SMTP são obrigatórios", variant: "destructive" });
        return;
      }
    } else if (
      emailSettings.authType === "oauth2_gmail" ||
      emailSettings.authType === "oauth2_microsoft"
    ) {
      if (!emailSettings.oauth2ClientId || (!emailSettings.oauth2ClientSecretPlain && !emailSettingsData)) {
        toast({ title: "Erro", description: "Client ID e Client Secret são obrigatórios para OAuth2", variant: "destructive" });
        return;
      }
      if (emailSettings.authType === "oauth2_gmail" && !emailSettings.oauth2RefreshTokenPlain && !emailSettingsData) {
        toast({ title: "Erro", description: "Refresh Token é obrigatório para Gmail", variant: "destructive" });
        return;
      }
      if (emailSettings.authType === "oauth2_microsoft" && !emailSettings.oauth2TenantId && !emailSettingsData) {
        toast({ title: "Erro", description: "Tenant ID é obrigatório para Microsoft 365", variant: "destructive" });
        return;
      }
    }
    await saveEmailSettingsMutation.mutateAsync(emailSettings);
  };

  const handleTestEmail = async () => {
    if (!testEmail) {
      toast({ title: "Erro", description: "Informe um e-mail para teste", variant: "destructive" });
      return;
    }
    await testEmailMutation.mutateAsync(testEmail);
  };

  if (currentUser?.role !== "global_administrator") return null;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Mensageria"
          subtitle="Provedor de email para notificações do sistema"
          wsConnected={connected}
        />
        <div className="p-6 space-y-6">
          <AdminBreadcrumb page="Mensageria" />

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Inbox className="h-5 w-5" />
                <span>Mensageria</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <p className="text-sm text-muted-foreground">
                Configure como o SamurEye envia e-mails de notificação. Escolha um provedor e
                preencha suas credenciais.
              </p>

              <div
                role="radiogroup"
                aria-label="Provedor de mensageria"
                className="grid grid-cols-1 gap-4 md:grid-cols-3"
              >
                <MessagingProviderCard
                  id="google"
                  name="Google Workspace"
                  subtitle="OAuth2 — recomendado"
                  logo={<GoogleWorkspaceLogo className="h-7 w-7" />}
                  selected={selectedProvider === "google"}
                  configured={isProviderConfigured("google")}
                  onSelect={() => handleSelectProvider("google")}
                  tabIndex={selectedProvider === "google" ? 0 : -1}
                  onKeyDown={handleProviderKeyDown("google")}
                />
                <MessagingProviderCard
                  id="microsoft"
                  name="Microsoft 365"
                  subtitle="OAuth2 — recomendado"
                  logo={<MicrosoftLogo className="h-7 w-7" />}
                  selected={selectedProvider === "microsoft"}
                  configured={isProviderConfigured("microsoft")}
                  onSelect={() => handleSelectProvider("microsoft")}
                  tabIndex={selectedProvider === "microsoft" ? 0 : -1}
                  onKeyDown={handleProviderKeyDown("microsoft")}
                />
                <MessagingProviderCard
                  id="smtp"
                  name="SMTP tradicional"
                  subtitle="Usuário e senha — legado"
                  logo={<ServerCog className="h-7 w-7 text-muted-foreground" />}
                  selected={selectedProvider === "smtp"}
                  configured={isProviderConfigured("smtp")}
                  onSelect={() => handleSelectProvider("smtp")}
                  tabIndex={selectedProvider === "smtp" ? 0 : -1}
                  onKeyDown={handleProviderKeyDown("smtp")}
                />
              </div>

              <MessagingProviderGuide
                provider={selectedProvider}
                defaultOpen={!isProviderConfigured(selectedProvider)}
              />

              {/* NOTE: assumes SMTP is the only non-OAuth2 provider. Revisit this branch if a new provider (e.g. SES, SendGrid) is added. */}
              {selectedProvider === "smtp" ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="smtpHost">Servidor SMTP</Label>
                      <Input
                        id="smtpHost"
                        placeholder="smtp.seudominio.com"
                        value={emailSettings.smtpHost}
                        onChange={(e) => handleEmailSettingChange("smtpHost", e.target.value)}
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
                        onChange={(e) =>
                          handleEmailSettingChange("smtpPort", parseInt(e.target.value))
                        }
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
                      onCheckedChange={(checked) =>
                        handleEmailSettingChange("smtpSecure", checked)
                      }
                      data-testid="switch-smtp-secure"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="authUser">Usuário SMTP</Label>
                      <Input
                        id="authUser"
                        placeholder="usuario@dominio.com"
                        value={emailSettings.authUser}
                        onChange={(e) => handleEmailSettingChange("authUser", e.target.value)}
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
                        onChange={(e) =>
                          handleEmailSettingChange("authPasswordPlain", e.target.value)
                        }
                        data-testid="input-auth-password"
                      />
                      <p className="text-sm text-muted-foreground mt-1">
                        Deixe em branco para manter a senha atual
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <p className="rounded-md border border-dashed border-border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
                    Servidor: <code>{emailSettings.smtpHost}</code> · Porta:{" "}
                    <code>{emailSettings.smtpPort}</code> · TLS via STARTTLS
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="oauth2ClientId">Client ID</Label>
                      <Input
                        id="oauth2ClientId"
                        placeholder={
                          selectedProvider === "google"
                            ? "seu-client-id.apps.googleusercontent.com"
                            : "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        }
                        value={emailSettings.oauth2ClientId}
                        onChange={(e) =>
                          handleEmailSettingChange("oauth2ClientId", e.target.value)
                        }
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
                        onChange={(e) =>
                          handleEmailSettingChange("oauth2ClientSecretPlain", e.target.value)
                        }
                        data-testid="input-oauth2-client-secret"
                      />
                      <p className="text-sm text-muted-foreground mt-1">
                        Deixe em branco para manter o secret atual
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {selectedProvider === "google" && (
                      <div>
                        <Label htmlFor="oauth2RefreshToken">Refresh Token</Label>
                        <Input
                          id="oauth2RefreshToken"
                          type="password"
                          placeholder="••••••••"
                          value={emailSettings.oauth2RefreshTokenPlain}
                          onChange={(e) =>
                            handleEmailSettingChange("oauth2RefreshTokenPlain", e.target.value)
                          }
                          data-testid="input-oauth2-refresh-token"
                        />
                        <p className="text-sm text-muted-foreground mt-1">
                          Deixe em branco para manter o token atual
                        </p>
                      </div>
                    )}
                    {selectedProvider === "microsoft" && (
                      <div>
                        <Label htmlFor="oauth2TenantId">Tenant ID</Label>
                        <Input
                          id="oauth2TenantId"
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          value={emailSettings.oauth2TenantId}
                          onChange={(e) =>
                            handleEmailSettingChange("oauth2TenantId", e.target.value)
                          }
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
                    onChange={(e) => handleEmailSettingChange("fromEmail", e.target.value)}
                    data-testid="input-from-email"
                  />
                </div>
                <div>
                  <Label htmlFor="fromName">Nome do Remetente</Label>
                  <Input
                    id="fromName"
                    placeholder="SamurEye Notificações"
                    value={emailSettings.fromName}
                    onChange={(e) => handleEmailSettingChange("fromName", e.target.value)}
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
                  {saveEmailSettingsMutation.isPending
                    ? "Salvando..."
                    : "Salvar configurações de mensageria"}
                </Button>
              </div>

              <Separator />

              <div className="space-y-2">
                <Label htmlFor="testEmail">Testar envio</Label>
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
                    {testEmailMutation.isPending ? "Enviando..." : "Enviar teste"}
                  </Button>
                </div>
                <p className="text-sm text-muted-foreground">
                  Envie um e-mail de teste para verificar se as configurações estão corretas
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
