import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import CredentialForm from "@/components/forms/credential-form";
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Plus, Search, Trash2, Key, Shield, Pencil } from "lucide-react";
import { Credential } from "@shared/schema";
import { CredentialFormData } from "@/types";

export default function Credentials() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingCredential, setEditingCredential] = useState<Omit<Credential, 'secretEncrypted' | 'dekEncrypted'> | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const { data: credentials = [], isLoading } = useQuery<Omit<Credential, 'secretEncrypted' | 'dekEncrypted'>[]>({
    queryKey: ["/api/credentials"],
  });

  const createCredentialMutation = useMutation({
    mutationFn: async (data: CredentialFormData) => {
      return await apiRequest('POST', '/api/credentials', data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Credencial criada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/credentials"] });
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
        description: "Falha ao criar credencial",
        variant: "destructive",
      });
    },
  });

  const updateCredentialMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: CredentialFormData }) => {
      return await apiRequest('PATCH', `/api/credentials/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Credencial atualizada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/credentials"] });
      setEditingCredential(null);
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
        description: "Falha ao atualizar credencial",
        variant: "destructive",
      });
    },
  });

  const deleteCredentialMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest('DELETE', `/api/credentials/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Credencial excluída com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/credentials"] });
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
        description: "Falha ao excluir credencial",
        variant: "destructive",
      });
    },
  });

  const filteredCredentials = credentials.filter(credential =>
    credential.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    credential.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
    credential.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleCreateCredential = (data: CredentialFormData) => {
    createCredentialMutation.mutate(data);
  };

  const handleUpdateCredential = (data: CredentialFormData) => {
    if (editingCredential) {
      updateCredentialMutation.mutate({ id: editingCredential.id, data });
    }
  };

  const [deleteCredentialId, setDeleteCredentialId] = useState<string | null>(null);

  const handleDeleteCredential = (id: string) => {
    setDeleteCredentialId(id);
  };

  const getCredentialTypeLabel = (type: string) => {
    switch (type) {
      case 'ssh':
        return 'SSH (Linux/Unix)';
      case 'wmi':
      case 'omi':
      case 'ad':
        return 'WMI (Windows)';
      default:
        return type.toUpperCase();
    }
  };

  const getCredentialTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'ssh':
        return 'bg-primary/20 text-primary';
      case 'wmi':
      case 'omi':
      case 'ad':
        return 'bg-accent/20 text-accent';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar
          title="Gestão de Credenciais"
          subtitle="Configure credenciais para acesso seguro aos sistemas"
          wsConnected={connected}
        />
        
        <div className="p-6 space-y-6">
          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar credenciais por nome, usuário ou tipo..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-credentials"
                  />
                </div>
                <Badge variant="secondary" data-testid="credentials-count">
                  {filteredCredentials.length} credenciais
                </Badge>
                <Button
                  onClick={() => setShowCreateDialog(true)}
                  data-testid="button-create-credential"
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Nova Credencial
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Security Notice */}
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="p-6">
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-primary mt-0.5" />
                <div>
                  <h3 className="font-medium text-foreground mb-1">
                    Segurança das Credenciais
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    Todas as credenciais são criptografadas usando AES-256-GCM com chaves de criptografia rotacionáveis. 
                    As senhas nunca são armazenadas em texto plano e só são descriptografadas no momento do uso.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Credentials Table */}
          <Card>
            <CardHeader>
              <CardTitle>Credenciais Cadastradas</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando credenciais...</p>
                </div>
              ) : filteredCredentials.length === 0 ? (
                <div className="text-center py-8">
                  <Key className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm ? 'Nenhuma credencial encontrada' : 'Nenhuma credencial cadastrada'}
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    {searchTerm 
                      ? 'Tente ajustar os termos de busca'
                      : 'Comece adicionando credenciais para acesso aos sistemas'
                    }
                  </p>
                  {!searchTerm && (
                    <Button onClick={() => setShowCreateDialog(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Adicionar Primeira Credencial
                    </Button>
                  )}
                </div>
              ) : (
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Nome</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Usuário</TableHead>
                      <TableHead>Host/Porta</TableHead>
                      <TableHead>Criada em</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredCredentials.map((credential) => (
                      <TableRow key={credential.id} data-testid={`credential-row-${credential.id}`}>
                        <TableCell className="font-medium">
                          {credential.name}
                        </TableCell>
                        <TableCell>
                          <Badge className={getCredentialTypeBadgeColor(credential.type)}>
                            {getCredentialTypeLabel(credential.type)}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono">
                          {credential.username}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {credential.hostOverride || 'Qualquer host'}
                          {credential.port && ` :${credential.port}`}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {new Date(credential.createdAt).toLocaleDateString('pt-BR')}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setEditingCredential(credential)}
                            className="text-muted-foreground hover:text-foreground mr-1"
                            data-testid={`button-edit-${credential.id}`}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteCredential(credential.id)}
                            className="text-destructive hover:text-destructive"
                            data-testid={`button-delete-${credential.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Create Credential Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Criar Nova Credencial</DialogTitle>
          </DialogHeader>
          <CredentialForm
            onSubmit={handleCreateCredential}
            onCancel={() => setShowCreateDialog(false)}
            isLoading={createCredentialMutation.isPending}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Credential Dialog */}
      <Dialog open={!!editingCredential} onOpenChange={(open) => !open && setEditingCredential(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Editar Credencial</DialogTitle>
          </DialogHeader>
          {editingCredential && (
            <CredentialForm
              onSubmit={handleUpdateCredential}
              onCancel={() => setEditingCredential(null)}
              isLoading={updateCredentialMutation.isPending}
              initialData={editingCredential}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Delete Credential Confirmation */}
      <AlertDialog open={!!deleteCredentialId} onOpenChange={(open) => !open && setDeleteCredentialId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Excluir Credencial</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja excluir esta credencial? Testes de segurança que a utilizam perderão o acesso a ela.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (deleteCredentialId) {
                  deleteCredentialMutation.mutate(deleteCredentialId);
                  setDeleteCredentialId(null);
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
