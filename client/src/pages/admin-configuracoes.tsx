// client/src/pages/admin-configuracoes.tsx
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Save, Globe, SlidersHorizontal } from "lucide-react";
import type { Setting } from "@shared/schema";

interface ConfiguracoesForm {
  systemName: string;
  systemDescription: string;
  systemTimezone: string;
  sessionTimeout: number;
  applianceName: string;
  locationType: string;
  locationDetail: string;
}

export default function AdminConfiguracoes() {
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const [formData, setFormData] = useState<ConfiguracoesForm>({
    systemName: "SamurEye",
    systemDescription: "Plataforma de Validação de Exposição Adversarial",
    systemTimezone: "America/Sao_Paulo",
    sessionTimeout: 3600,
    applianceName: "",
    locationType: "",
    locationDetail: "",
  });

  const { data: settings = [], isLoading } = useQuery<Setting[]>({
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
      setFormData((prev) => {
        const next = { ...prev };
        settings.forEach((s) => {
          if (s.key in next) (next as any)[s.key] = s.value;
        });
        return next;
      });
    }
  }, [settings]);

  const handleInputChange = (key: keyof ConfiguracoesForm, value: any) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    const updates = Object.entries(formData).map(([key, value]) => ({ key, value }));
    try {
      await Promise.all(updates.map((u) => updateSettingMutation.mutateAsync(u)));
      toast({ title: "Sucesso", description: "Configurações salvas com sucesso" });
      apiRequest("POST", "/api/appliance/heartbeat-now").catch(() => {});
    } catch {
      // errors handled in mutation
    }
  };

  if (currentUser?.role !== "global_administrator") return null;

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Configurações Gerais"
          subtitle="Nome do sistema, timezone, localização e appliance"
          wsConnected={connected}
        />
        <div className="p-6 space-y-6">
          <AdminBreadcrumb page="Configurações Gerais" />

          <div className="flex justify-end">
            <Button
              onClick={handleSave}
              disabled={updateSettingMutation.isPending}
              data-testid="button-save-settings"
            >
              <Save className="mr-2 h-4 w-4" />
              {updateSettingMutation.isPending ? "Salvando..." : "Salvar Alterações"}
            </Button>
          </div>

          {isLoading ? (
            <div className="text-center py-8">
              <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-muted-foreground">Carregando configurações...</p>
            </div>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <SlidersHorizontal className="h-5 w-5" />
                  <span>Configurações Gerais</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="systemName">Nome do Sistema</Label>
                  <Input
                    id="systemName"
                    value={formData.systemName}
                    onChange={(e) => handleInputChange("systemName", e.target.value)}
                    data-testid="input-system-name"
                  />
                </div>

                <div>
                  <Label htmlFor="systemDescription">Descrição</Label>
                  <Textarea
                    id="systemDescription"
                    value={formData.systemDescription}
                    onChange={(e) => handleInputChange("systemDescription", e.target.value)}
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
                    onValueChange={(v) => handleInputChange("systemTimezone", v)}
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
                    onChange={(e) => handleInputChange("sessionTimeout", parseInt(e.target.value))}
                    data-testid="input-session-timeout"
                  />
                  <p className="text-sm text-muted-foreground mt-1">
                    Tempo para expirar sessões inativas
                  </p>
                </div>

                <Separator />

                <div>
                  <h4 className="text-base font-semibold">Identificação e Localização</h4>
                  <p className="mt-2 rounded-md border border-dashed border-border bg-muted/20 px-3 py-2 text-sm text-muted-foreground">
                    Estes campos são enviados ao console no próximo heartbeat e usados para
                    organizar seus appliances por localização.
                  </p>
                </div>

                <div>
                  <Label htmlFor="applianceName">Nome do Appliance</Label>
                  <Input
                    id="applianceName"
                    value={formData.applianceName}
                    maxLength={100}
                    onChange={(e) => handleInputChange("applianceName", e.target.value)}
                    placeholder="sam-sp-dc01"
                    data-testid="input-appliance-name"
                  />
                  <p className="text-sm text-muted-foreground mt-1">
                    Um apelido amigável para identificar este appliance. Aparece no dashboard do
                    cliente e na página de detalhe.
                  </p>
                </div>

                <div>
                  <Label htmlFor="locationType">Tipo de Localização</Label>
                  <Select
                    value={formData.locationType || "__none__"}
                    onValueChange={(v) =>
                      handleInputChange("locationType", v === "__none__" ? "" : v)
                    }
                  >
                    <SelectTrigger id="locationType" data-testid="select-location-type">
                      <SelectValue placeholder="Não definido" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__none__">Não definido</SelectItem>
                      <SelectItem value="matriz">Matriz</SelectItem>
                      <SelectItem value="filial">Filial</SelectItem>
                      <SelectItem value="datacenter">Datacenter</SelectItem>
                      <SelectItem value="nuvem">Nuvem</SelectItem>
                      <SelectItem value="outro">Outro</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground mt-1">
                    Appliances com o mesmo tipo e detalhe serão agrupados no painel do cliente.
                  </p>
                </div>

                <div>
                  <Label htmlFor="locationDetail">Detalhes da Localização</Label>
                  <Input
                    id="locationDetail"
                    value={formData.locationDetail}
                    maxLength={200}
                    onChange={(e) => handleInputChange("locationDetail", e.target.value)}
                    placeholder="DC Equinix SP4 - Sala 3"
                    data-testid="input-location-detail"
                  />
                  <p className="text-sm text-muted-foreground mt-1">
                    Complemento que torna a localização única (ex.: AWS us-east-1, DC Equinix SP4).
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </main>
    </div>
  );
}
