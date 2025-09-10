import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
import { Search, Users, Worm, ArrowRight } from "lucide-react";

export default function QuickActions() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const executeJobMutation = useMutation({
    mutationFn: async (journeyId: string) => {
      return await apiRequest('POST', '/api/jobs/execute', { journeyId });
    },
    onSuccess: () => {
      toast({
        title: "Job Iniciado",
        description: "A jornada foi adicionada à fila de execução",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/running-jobs"] });
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

  const quickActions = [
    {
      title: "Attack Surface",
      description: "Scan de rede completo",
      icon: Search,
      iconBg: "bg-primary/20",
      iconColor: "text-primary",
      action: () => {
        // For demo purposes, we'll show a message since we don't have predefined journeys
        toast({
          title: "Attack Surface",
          description: "Configurar jornada de Attack Surface primeiro em Jornadas",
          variant: "default",
        });
      },
    },
    {
      title: "Higiene AD",
      description: "Análise de Active Directory",
      icon: Users,
      iconBg: "bg-accent/20",
      iconColor: "text-accent",
      action: () => {
        toast({
          title: "Higiene AD",
          description: "Configurar jornada de Higiene AD primeiro em Jornadas",
          variant: "default",
        });
      },
    },
    {
      title: "Teste EDR/AV",
      description: "Validação com EICAR",
      icon: Worm,
      iconBg: "bg-chart-5/20",
      iconColor: "text-chart-5",
      action: () => {
        toast({
          title: "Teste EDR/AV",
          description: "Configurar jornada de Teste EDR/AV primeiro em Jornadas",
          variant: "default",
        });
      },
    },
  ];

  return (
    <Card className="bg-card border-border">
      <CardHeader className="border-b border-border">
        <CardTitle className="text-lg font-semibold text-foreground">
          Jornadas Rápidas
        </CardTitle>
        <p className="text-sm text-muted-foreground">Executar verificações comuns</p>
      </CardHeader>
      <CardContent className="p-6">
        <div className="space-y-3">
          {quickActions.map((action, index) => (
            <Button
              key={index}
              variant="ghost"
              className="w-full flex items-center justify-between p-4 bg-muted/50 hover:bg-muted rounded-lg transition-colors h-auto"
              onClick={action.action}
              disabled={executeJobMutation.isPending}
              data-testid={`quick-action-${action.title.toLowerCase().replace(/\s+/g, '-')}`}
            >
              <div className="flex items-center space-x-3">
                <div className={`w-8 h-8 ${action.iconBg} rounded-lg flex items-center justify-center`}>
                  <action.icon className={`${action.iconColor} h-4 w-4`} />
                </div>
                <div className="text-left">
                  <p className="font-medium text-foreground">{action.title}</p>
                  <p className="text-xs text-muted-foreground">{action.description}</p>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
