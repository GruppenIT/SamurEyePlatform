import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import AssetForm from "@/components/forms/asset-form";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Plus, Search, Edit, Trash2, Server, Globe } from "lucide-react";
import { Asset } from "@shared/schema";
import { AssetFormData } from "@/types";

export default function Assets() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: assets = [], isLoading } = useQuery<Asset[]>({
    queryKey: ["/api/assets"],
  });

  const createAssetMutation = useMutation({
    mutationFn: async (data: AssetFormData) => {
      return await apiRequest('POST', '/api/assets', data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Alvo criado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
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
        description: "Falha ao criar alvo",
        variant: "destructive",
      });
    },
  });

  const updateAssetMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<AssetFormData> }) => {
      return await apiRequest('PATCH', `/api/assets/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Alvo atualizado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      setEditingAsset(null);
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
        description: "Falha ao atualizar alvo",
        variant: "destructive",
      });
    },
  });

  const deleteAssetMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest('DELETE', `/api/assets/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Alvo excluído com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
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
        description: "Falha ao excluir alvo",
        variant: "destructive",
      });
    },
  });

  const filteredAssets = assets.filter(asset =>
    asset.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
    asset.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const handleCreateAsset = (data: AssetFormData) => {
    createAssetMutation.mutate(data);
  };

  const handleUpdateAsset = (data: AssetFormData) => {
    if (editingAsset) {
      updateAssetMutation.mutate({ id: editingAsset.id, data });
    }
  };

  const handleDeleteAsset = (id: string) => {
    if (confirm('Tem certeza que deseja excluir este alvo?')) {
      deleteAssetMutation.mutate(id);
    }
  };

  const getAssetIcon = (type: string) => {
    return type === 'host' ? Server : Globe;
  };

  const getAssetTypeLabel = (type: string) => {
    return type === 'host' ? 'Host Individual' : 'Faixa de IPs';
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Gestão de Alvos"
          subtitle="Configure e gerencie hosts e faixas de IP para monitoramento"
          actions={
            <Button
              onClick={() => setShowCreateDialog(true)}
              data-testid="button-create-asset"
            >
              <Plus className="mr-2 h-4 w-4" />
              Novo Alvo
            </Button>
          }
        />
        
        <div className="p-6 space-y-6">
          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar alvos por valor ou tag..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-assets"
                  />
                </div>
                <Badge variant="secondary" data-testid="assets-count">
                  {filteredAssets.length} alvos
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Assets Table */}
          <Card>
            <CardHeader>
              <CardTitle>Alvos Cadastrados</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando alvos...</p>
                </div>
              ) : filteredAssets.length === 0 ? (
                <div className="text-center py-8">
                  <Server className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm ? 'Nenhum alvo encontrado' : 'Nenhum alvo cadastrado'}
                  </h3>
                  <p className="text-muted-foreground mb-4">
                    {searchTerm 
                      ? 'Tente ajustar os termos de busca'
                      : 'Comece adicionando seu primeiro alvo para monitoramento'
                    }
                  </p>
                  {!searchTerm && (
                    <Button onClick={() => setShowCreateDialog(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Adicionar Primeiro Alvo
                    </Button>
                  )}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Valor</TableHead>
                      <TableHead>Tags</TableHead>
                      <TableHead>Criado em</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAssets.map((asset) => {
                      const Icon = getAssetIcon(asset.type);
                      return (
                        <TableRow key={asset.id} data-testid={`asset-row-${asset.id}`}>
                          <TableCell>
                            <div className="flex items-center space-x-2">
                              <Icon className="h-4 w-4 text-muted-foreground" />
                              <span>{getAssetTypeLabel(asset.type)}</span>
                            </div>
                          </TableCell>
                          <TableCell className="font-mono">
                            {asset.value}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {asset.tags.map((tag, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {new Date(asset.createdAt).toLocaleDateString('pt-BR')}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="flex justify-end space-x-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setEditingAsset(asset)}
                                data-testid={`button-edit-${asset.id}`}
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDeleteAsset(asset.id)}
                                className="text-destructive hover:text-destructive"
                                data-testid={`button-delete-${asset.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Create Asset Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Criar Novo Alvo</DialogTitle>
          </DialogHeader>
          <AssetForm
            onSubmit={handleCreateAsset}
            onCancel={() => setShowCreateDialog(false)}
            isLoading={createAssetMutation.isPending}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Asset Dialog */}
      <Dialog open={!!editingAsset} onOpenChange={() => setEditingAsset(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Editar Alvo</DialogTitle>
          </DialogHeader>
          {editingAsset && (
            <AssetForm
              onSubmit={handleUpdateAsset}
              onCancel={() => setEditingAsset(null)}
              isLoading={updateAssetMutation.isPending}
              initialData={{
                type: editingAsset.type,
                value: editingAsset.value,
                tags: editingAsset.tags,
              }}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
