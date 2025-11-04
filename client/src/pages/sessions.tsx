import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
import { Smartphone, LogOut, Shield } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { ptBR } from "date-fns/locale";

interface ActiveSession {
  id: string;
  sessionId: string;
  userId: string;
  sessionVersion: number;
  ipAddress: string;
  userAgent: string;
  deviceInfo: string;
  createdAt: string;
  lastActivity: string;
  expiresAt: string;
  isCurrent?: boolean;
}

export default function Sessions() {
  const [revokeSessionId, setRevokeSessionId] = useState<string | null>(null);
  const [showRevokeAllDialog, setShowRevokeAllDialog] = useState(false);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch active sessions
  const { data: sessions = [], isLoading } = useQuery<ActiveSession[]>({
    queryKey: ['/api/sessions'],
  });

  // Revoke single session mutation
  const revokeSessionMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      return await apiRequest('DELETE', `/api/sessions/${sessionId}`);
    },
    onSuccess: () => {
      toast({
        title: "Sessão Revogada",
        description: "A sessão foi encerrada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sessions"] });
      setRevokeSessionId(null);
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Não autorizado",
          description: "Você foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: error.message || "Falha ao revogar sessão",
        variant: "destructive",
      });
      setRevokeSessionId(null);
    },
  });

  // Revoke all sessions mutation
  const revokeAllSessionsMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest('DELETE', '/api/sessions');
    },
    onSuccess: () => {
      toast({
        title: "Sessões Revogadas",
        description: "Todas as suas sessões foram encerradas. Você será redirecionado para o login.",
      });
      setShowRevokeAllDialog(false);
      // Redirecionar para login após 1 segundo
      setTimeout(() => {
        window.location.href = "/login";
      }, 1000);
    },
    onError: (error: any) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Não autorizado",
          description: "Você foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: error.message || "Falha ao revogar sessões",
        variant: "destructive",
      });
      setShowRevokeAllDialog(false);
    },
  });

  const getSessionBadge = (session: ActiveSession) => {
    if (session.isCurrent) {
      return <Badge variant="default" className="bg-green-600 text-white">Sessão Atual</Badge>;
    }
    return null;
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar title="Sessões Ativas" subtitle="Gerencie suas sessões" />
        
        <main className="flex-1 overflow-auto p-8">
          <div className="max-w-7xl mx-auto space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-foreground">Sessões Ativas</h1>
                <p className="text-muted-foreground mt-1">
                  Gerencie todas as suas sessões ativas em diferentes dispositivos
                </p>
              </div>
              
              <Button
                data-testid="button-revoke-all-sessions"
                variant="destructive"
                onClick={() => setShowRevokeAllDialog(true)}
                disabled={sessions.length === 0 || revokeAllSessionsMutation.isPending}
              >
                <LogOut className="mr-2 h-4 w-4" />
                Encerrar Todas as Sessões
              </Button>
            </div>

            {/* Sessions Table */}
            <Card>
              <CardHeader>
                <CardTitle>Dispositivos Conectados</CardTitle>
                <CardDescription>
                  {sessions.length === 0 
                    ? "Nenhuma sessão ativa encontrada" 
                    : `${sessions.length} ${sessions.length === 1 ? 'dispositivo conectado' : 'dispositivos conectados'}`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="text-center py-8 text-muted-foreground">
                    Carregando sessões...
                  </div>
                ) : sessions.length === 0 ? (
                  <div className="text-center py-12">
                    <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                    <p className="text-muted-foreground">
                      Nenhuma sessão ativa encontrada
                    </p>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Dispositivo</TableHead>
                          <TableHead>Endereço IP</TableHead>
                          <TableHead>Última Atividade</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Ações</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {sessions.map((session) => (
                          <TableRow key={session.id} data-testid={`row-session-${session.id}`}>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <Smartphone className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <div className="font-medium" data-testid={`text-device-${session.id}`}>
                                    {session.deviceInfo}
                                  </div>
                                  <div className="text-sm text-muted-foreground">
                                    Criado {formatDistanceToNow(new Date(session.createdAt), { 
                                      addSuffix: true, 
                                      locale: ptBR 
                                    })}
                                  </div>
                                </div>
                              </div>
                            </TableCell>
                            <TableCell data-testid={`text-ip-${session.id}`}>
                              {session.ipAddress}
                            </TableCell>
                            <TableCell data-testid={`text-activity-${session.id}`}>
                              {formatDistanceToNow(new Date(session.lastActivity), { 
                                addSuffix: true, 
                                locale: ptBR 
                              })}
                            </TableCell>
                            <TableCell>
                              {getSessionBadge(session)}
                            </TableCell>
                            <TableCell className="text-right">
                              {!session.isCurrent && (
                                <Button
                                  data-testid={`button-revoke-${session.id}`}
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => setRevokeSessionId(session.sessionId)}
                                  disabled={revokeSessionMutation.isPending}
                                >
                                  <LogOut className="h-4 w-4 mr-2" />
                                  Encerrar
                                </Button>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Security Info */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Segurança da Conta
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-sm text-muted-foreground space-y-2">
                  <p>
                    <strong>Sobre as Sessões:</strong> Cada vez que você faz login em um novo dispositivo ou navegador, 
                    uma nova sessão é criada. Você pode encerrar qualquer sessão que não reconheça.
                  </p>
                  <p>
                    <strong>Segurança:</strong> Todas as sessões expiram automaticamente após 8 horas de inatividade. 
                    Se você reiniciar o servidor, todas as sessões anteriores serão invalidadas por segurança.
                  </p>
                  <p>
                    <strong>Recomendação:</strong> Revise regularmente suas sessões ativas e encerre aquelas que você 
                    não reconheça ou de dispositivos que não utiliza mais.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>

      {/* Revoke Single Session Dialog */}
      <AlertDialog open={!!revokeSessionId} onOpenChange={() => setRevokeSessionId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Encerrar Sessão</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja encerrar esta sessão? O dispositivo precisará fazer login novamente.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="button-cancel-revoke">Cancelar</AlertDialogCancel>
            <AlertDialogAction
              data-testid="button-confirm-revoke"
              onClick={() => {
                if (revokeSessionId) {
                  revokeSessionMutation.mutate(revokeSessionId);
                }
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Encerrar Sessão
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Revoke All Sessions Dialog */}
      <AlertDialog open={showRevokeAllDialog} onOpenChange={setShowRevokeAllDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Encerrar Todas as Sessões</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja encerrar todas as suas sessões? Você será desconectado de todos os dispositivos, 
              incluindo este, e precisará fazer login novamente.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="button-cancel-revoke-all">Cancelar</AlertDialogCancel>
            <AlertDialogAction
              data-testid="button-confirm-revoke-all"
              onClick={() => revokeAllSessionsMutation.mutate()}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Encerrar Todas
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
