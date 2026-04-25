import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest, apiFetch } from "@/lib/queryClient";
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
import { Plus, Search, Edit, Trash2, Server, Globe, ChevronRight, ChevronDown } from "lucide-react";
import { Asset } from "@shared/schema";
import { AssetFormData } from "@/types";

type AssetWithChildren = Asset & { children?: Asset[] };

type AssetViewMode = "tree" | "flat";
const VIEW_KEY = "samureye:assets:view";

function matchesSearch(asset: AssetWithChildren, term: string): boolean {
  if (!term) return true;
  const needle = term.toLowerCase();
  const own =
    asset.value.toLowerCase().includes(needle) ||
    (asset.tags ?? []).some((t: string) => t.toLowerCase().includes(needle));
  if (own) return true;
  return (asset.children ?? []).some((c) => matchesSearch(c as AssetWithChildren, term));
}

interface AssetRowProps {
  asset: Asset;
  depth: number;
  hasChildren?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
  childCount?: number;
  onEdit: (asset: Asset) => void;
  onDelete: (id: string) => void;
  getAssetIcon: (type: string) => React.ComponentType<{ className?: string }>;
  getAssetTypeLabel: (type: string) => string;
}

function AssetRow({
  asset,
  depth,
  hasChildren = false,
  expanded = false,
  onToggle,
  childCount = 0,
  onEdit,
  onDelete,
  getAssetIcon,
  getAssetTypeLabel,
}: AssetRowProps) {
  const Icon = getAssetIcon(asset.type);
  return (
    <TableRow
      key={asset.id}
      data-testid={`asset-row-${asset.id}`}
      className={depth > 0 ? "bg-muted/30" : undefined}
    >
      <TableCell>
        <div className="flex items-center space-x-2" style={depth > 0 ? { paddingLeft: "2rem" } : undefined}>
          {hasChildren && depth === 0 ? (
            <button
              onClick={onToggle}
              className="mr-1 text-muted-foreground hover:text-foreground focus:outline-none"
              aria-label={expanded ? "Recolher" : "Expandir"}
            >
              {expanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </button>
          ) : (
            depth === 0 && <span className="inline-block w-5" />
          )}
          <Icon className="h-4 w-4 text-muted-foreground" />
          <span>{getAssetTypeLabel(asset.type)}</span>
        </div>
      </TableCell>
      <TableCell className="font-mono">
        {depth > 0 ? (
          <span className="pl-8">{asset.value}</span>
        ) : (
          <span>
            {asset.value}
            {hasChildren && childCount > 0 && (
              <span className="ml-2 text-xs text-muted-foreground font-sans">
                ({childCount} web {childCount === 1 ? "app" : "apps"})
              </span>
            )}
          </span>
        )}
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
        {new Date(asset.createdAt).toLocaleDateString("pt-BR")}
      </TableCell>
      <TableCell className="text-right">
        <div className="flex justify-end space-x-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onEdit(asset)}
            data-testid={`button-edit-${asset.id}`}
          >
            <Edit className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onDelete(asset.id)}
            className="text-destructive hover:text-destructive"
            data-testid={`button-delete-${asset.id}`}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

export default function Assets() {
  const [searchTerm, setSearchTerm] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);

  const [viewMode, setViewMode] = useState<AssetViewMode>(() => {
    if (typeof window === "undefined") return "tree";
    const v = window.localStorage.getItem(VIEW_KEY);
    return v === "flat" || v === "tree" ? v : "tree";
  });

  useEffect(() => {
    if (typeof window !== "undefined") window.localStorage.setItem(VIEW_KEY, viewMode);
  }, [viewMode]);

  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

  const toggleHost = (id: string) => {
    setExpandedHosts((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  const { data: assets = [], isLoading } = useQuery<AssetWithChildren[]>({
    queryKey: ["/api/assets", viewMode],
    queryFn: async () => {
      const url = viewMode === "flat" ? "/api/assets?flat=1" : "/api/assets";
      const res = await apiFetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch assets");
      return res.json();
    },
  });

  // Auto-expand parents when search matches a child
  useEffect(() => {
    if (!searchTerm || viewMode !== "tree") return;
    const toExpand = new Set<string>();
    for (const a of assets) {
      if ((a.children ?? []).some((c) => matchesSearch(c as AssetWithChildren, searchTerm))) {
        toExpand.add(a.id);
      }
    }
    setExpandedHosts(toExpand);
  }, [searchTerm, viewMode, assets]);

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

  const filteredAssets = assets.filter((a) => matchesSearch(a, searchTerm));

  const handleCreateAsset = (data: AssetFormData) => {
    createAssetMutation.mutate(data);
  };

  const handleUpdateAsset = (data: AssetFormData) => {
    if (editingAsset) {
      updateAssetMutation.mutate({ id: editingAsset.id, data });
    }
  };

  const [deleteAssetId, setDeleteAssetId] = useState<string | null>(null);

  const handleDeleteAsset = (id: string) => {
    setDeleteAssetId(id);
  };

  const getAssetIcon = (type: string) => {
    if (type === 'host') return Server;
    if (type === 'web_application') return Globe;
    return Globe; // range (Faixa de IPs)
  };

  const getAssetTypeLabel = (type: string) => {
    if (type === 'host') return 'Host Individual';
    if (type === 'web_application') return 'Aplicação Web';
    return 'Faixa de IPs'; // range
  };

  const rowProps = {
    onEdit: setEditingAsset,
    onDelete: handleDeleteAsset,
    getAssetIcon,
    getAssetTypeLabel,
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <main className="flex-1 overflow-auto">
        <TopBar
          title="Gestão de Alvos"
          subtitle="Configure e gerencie hosts e faixas de IP para monitoramento"
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
                    placeholder="Buscar alvos por valor ou tag..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-assets"
                  />
                </div>
                <div className="inline-flex rounded-md border" data-testid="asset-view-toggle">
                  <Button
                    variant={viewMode === "tree" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setViewMode("tree")}
                  >
                    Árvore
                  </Button>
                  <Button
                    variant={viewMode === "flat" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setViewMode("flat")}
                  >
                    Plano
                  </Button>
                </div>
                <Badge variant="secondary" data-testid="assets-count">
                  {filteredAssets.length} alvos
                </Badge>
                <Button
                  onClick={() => setShowCreateDialog(true)}
                  data-testid="button-create-asset"
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Novo Alvo
                </Button>
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
                <div className="overflow-x-auto">
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
                    {viewMode === "flat" ? (
                      filteredAssets.map((asset) => (
                        <AssetRow key={asset.id} asset={asset} depth={0} {...rowProps} />
                      ))
                    ) : (
                      filteredAssets.flatMap((asset) => {
                        const childCount = asset.children?.length ?? 0;
                        const rows: React.ReactNode[] = [
                          <AssetRow
                            key={asset.id}
                            asset={asset}
                            depth={0}
                            hasChildren={childCount > 0}
                            expanded={expandedHosts.has(asset.id)}
                            onToggle={() => toggleHost(asset.id)}
                            childCount={childCount}
                            {...rowProps}
                          />,
                        ];
                        if (expandedHosts.has(asset.id)) {
                          for (const child of asset.children ?? []) {
                            if (searchTerm && !matchesSearch(child as AssetWithChildren, searchTerm)) continue;
                            rows.push(
                              <AssetRow
                                key={child.id}
                                asset={child}
                                depth={1}
                                {...rowProps}
                              />
                            );
                          }
                        }
                        return rows;
                      })
                    )}
                  </TableBody>
                </Table>
                </div>
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
              mode="edit"
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

      {/* Delete Asset Confirmation */}
      <AlertDialog open={!!deleteAssetId} onOpenChange={(open) => !open && setDeleteAssetId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Excluir Alvo</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja excluir este alvo? Hosts descobertos por este alvo não serão removidos.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (deleteAssetId) {
                  deleteAssetMutation.mutate(deleteAssetId);
                  setDeleteAssetId(null);
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
