// client/src/pages/admin-seguranca.tsx
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
import { Save, Shield } from "lucide-react";
import type { Setting } from "@shared/schema";

interface SegurancaForm {
  maxConcurrentJobs: number;
  jobTimeout: number;
}

export default function AdminSeguranca() {
  const { toast } = useToast();
  const { user: currentUser } = useAuth();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const [formData, setFormData] = useState<SegurancaForm>({
    maxConcurrentJobs: 3,
    jobTimeout: 1800,
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

  const handleInputChange = (key: keyof SegurancaForm, value: any) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    const updates = Object.entries(formData).map(([key, value]) => ({ key, value }));
    try {
      await Promise.all(updates.map((u) => updateSettingMutation.mutateAsync(u)));
      toast({ title: "Sucesso", description: "Configurações salvas com sucesso" });
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
          title="Segurança Operacional"
          subtitle="Limites de jobs concorrentes e timeouts"
          wsConnected={connected}
        />
        <div className="p-6 space-y-6">
          <AdminBreadcrumb page="Segurança Operacional" />

          <div className="flex justify-end">
            <Button
              onClick={handleSave}
              disabled={updateSettingMutation.isPending}
              data-testid="button-save-seguranca"
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
                  <Shield className="h-5 w-5" />
                  <span>Segurança Operacional</span>
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
                    onChange={(e) =>
                      handleInputChange("maxConcurrentJobs", parseInt(e.target.value))
                    }
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
                    onChange={(e) =>
                      handleInputChange("jobTimeout", parseInt(e.target.value))
                    }
                    data-testid="input-job-timeout"
                  />
                  <p className="text-sm text-muted-foreground mt-1">
                    Tempo máximo para execução de um job
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
