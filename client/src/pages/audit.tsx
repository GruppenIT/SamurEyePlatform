import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Search, History, User, Edit, Trash2, Plus, Settings, Shield, Eye } from "lucide-react";
import { AuditLogEntry } from "@shared/schema";

interface EnrichedAuditLogEntry extends AuditLogEntry {
  actorName?: string | null;
  actorEmail?: string | null;
  objectDetails?: {
    name?: string;
    type?: string;
    value?: string;
    username?: string;
    email?: string;
    role?: string;
    title?: string;
    severity?: string;
    status?: string;
  } | null;
}

export default function Audit() {
  const [searchTerm, setSearchTerm] = useState("");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [objectTypeFilter, setObjectTypeFilter] = useState<string>("all");
  const [selectedEntry, setSelectedEntry] = useState<EnrichedAuditLogEntry | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  
  const { toast } = useToast();
  const { user: currentUser } = useAuth();

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

  const { data: auditLog = [], isLoading } = useQuery<EnrichedAuditLogEntry[]>({
    queryKey: ["/api/audit", { limit: 100 }],
    enabled: currentUser?.role === 'global_administrator',
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const filteredAuditLog = auditLog.filter(entry => {
    const matchesSearch = entry.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      entry.objectType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (entry.objectId && entry.objectId.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesAction = actionFilter === "all" || entry.action === actionFilter;
    const matchesObjectType = objectTypeFilter === "all" || entry.objectType === objectTypeFilter;
    
    return matchesSearch && matchesAction && matchesObjectType;
  });

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'create':
        return Plus;
      case 'update':
        return Edit;
      case 'delete':
        return Trash2;
      case 'execute':
        return Settings;
      case 'update_role':
        return Shield;
      default:
        return History;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'create':
        return 'bg-chart-4/20 text-chart-4';
      case 'update':
        return 'bg-primary/20 text-primary';
      case 'delete':
        return 'bg-destructive/20 text-destructive';
      case 'execute':
        return 'bg-accent/20 text-accent';
      case 'update_role':
        return 'bg-orange-500/20 text-orange-500';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  const getActionLabel = (action: string) => {
    switch (action) {
      case 'create':
        return 'Criação';
      case 'update':
        return 'Atualização';
      case 'delete':
        return 'Exclusão';
      case 'execute':
        return 'Execução';
      case 'update_role':
        return 'Alteração de Papel';
      default:
        return action.charAt(0).toUpperCase() + action.slice(1);
    }
  };

  const getObjectTypeLabel = (objectType: string) => {
    switch (objectType) {
      case 'user':
        return 'Usuário';
      case 'asset':
        return 'Ativo';
      case 'credential':
        return 'Credencial';
      case 'journey':
        return 'Jornada';
      case 'schedule':
        return 'Agendamento';
      case 'job':
        return 'Job';
      case 'threat':
        return 'Ameaça';
      case 'setting':
        return 'Configuração';
      default:
        return objectType.charAt(0).toUpperCase() + objectType.slice(1);
    }
  };

  const formatTimestamp = (timestamp: string | Date) => {
    return new Date(timestamp).toLocaleString('pt-BR');
  };

  const uniqueActions = Array.from(new Set(auditLog.map(entry => entry.action)));
  const uniqueObjectTypes = Array.from(new Set(auditLog.map(entry => entry.objectType)));

  // Don't render if not admin
  if (currentUser?.role !== 'global_administrator') {
    return null;
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />
      
      <main className="flex-1 overflow-auto">
        <TopBar 
          title="Log de Auditoria"
          subtitle="Acompanhe todas as ações administrativas do sistema"
        />
        
        <div className="p-6 space-y-6">
          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar por ação, tipo de objeto ou ID..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-audit"
                  />
                </div>
                <Select value={actionFilter} onValueChange={setActionFilter}>
                  <SelectTrigger className="w-48" data-testid="select-action-filter">
                    <SelectValue placeholder="Filtrar por ação" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todas as Ações</SelectItem>
                    {uniqueActions.map((action) => (
                      <SelectItem key={action} value={action}>
                        {getActionLabel(action)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={objectTypeFilter} onValueChange={setObjectTypeFilter}>
                  <SelectTrigger className="w-48" data-testid="select-object-filter">
                    <SelectValue placeholder="Filtrar por tipo" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Tipos</SelectItem>
                    {uniqueObjectTypes.map((objectType) => (
                      <SelectItem key={objectType} value={objectType}>
                        {getObjectTypeLabel(objectType)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Badge variant="secondary" data-testid="audit-count">
                  {filteredAuditLog.length} entradas
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Audit Information */}
          <Card className="border-primary/20 bg-primary/5">
            <CardContent className="p-6">
              <div className="flex items-start space-x-3">
                <History className="h-5 w-5 text-primary mt-0.5" />
                <div>
                  <h3 className="font-medium text-foreground mb-1">
                    Auditoria de Segurança
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    Todas as ações administrativas são registradas para conformidade e rastreabilidade. 
                    Os logs incluem informações do usuário, timestamps e detalhes das alterações realizadas.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Audit Log Table */}
          <Card>
            <CardHeader>
              <CardTitle>Registro de Atividades</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
                  <p className="text-muted-foreground">Carregando log de auditoria...</p>
                </div>
              ) : filteredAuditLog.length === 0 ? (
                <div className="text-center py-8">
                  <History className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm || actionFilter !== "all" || objectTypeFilter !== "all" ? 
                      'Nenhuma entrada encontrada' : 'Nenhuma atividade registrada'
                    }
                  </h3>
                  <p className="text-muted-foreground">
                    {searchTerm || actionFilter !== "all" || objectTypeFilter !== "all" 
                      ? 'Tente ajustar os filtros de busca'
                      : 'Ações administrativas aparecerão aqui'
                    }
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Data/Hora</TableHead>
                        <TableHead>Usuário</TableHead>
                        <TableHead>Ação</TableHead>
                        <TableHead>Tipo de Objeto</TableHead>
                        <TableHead>Objeto</TableHead>
                        <TableHead className="text-right">Ações</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredAuditLog.map((entry) => {
                        const ActionIcon = getActionIcon(entry.action);
                        return (
                          <TableRow key={entry.id} data-testid={`audit-row-${entry.id}`}>
                            <TableCell className="text-muted-foreground font-mono text-sm">
                              {formatTimestamp(entry.createdAt)}
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center space-x-2">
                                <User className="h-4 w-4 text-muted-foreground" />
                                <div>
                                  <div className="font-medium">
                                    {entry.actorName || 'Usuário Sistema'}
                                  </div>
                                  {entry.actorEmail && (
                                    <div className="text-xs text-muted-foreground">
                                      {entry.actorEmail}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center space-x-2">
                                <ActionIcon className="h-4 w-4" />
                                <Badge className={getActionColor(entry.action)}>
                                  {getActionLabel(entry.action)}
                                </Badge>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">
                                {getObjectTypeLabel(entry.objectType)}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {entry.objectDetails ? (
                                <div>
                                  <div className="font-medium text-sm">
                                    {entry.objectDetails.name || entry.objectDetails.title || '-'}
                                  </div>
                                  <div className="text-xs text-muted-foreground">
                                    {entry.objectDetails.type && `Tipo: ${entry.objectDetails.type}`}
                                    {entry.objectDetails.username && `User: ${entry.objectDetails.username}`}
                                    {entry.objectDetails.email && entry.objectDetails.email}
                                    {entry.objectDetails.value && entry.objectDetails.value}
                                  </div>
                                </div>
                              ) : entry.objectId ? (
                                <span className="font-mono text-xs text-muted-foreground">
                                  {entry.objectId.slice(0, 8)}...
                                </span>
                              ) : (
                                '-'
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  setSelectedEntry(entry);
                                  setDetailsOpen(true);
                                }}
                                data-testid={`button-view-details-${entry.id}`}
                              >
                                <Eye className="h-4 w-4 mr-1" />
                                Detalhes
                              </Button>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Details Dialog */}
      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Detalhes da Atividade de Auditoria</DialogTitle>
            <DialogDescription>
              Informações completas sobre a ação executada
            </DialogDescription>
          </DialogHeader>
          
          {selectedEntry && (
            <div className="space-y-6">
              {/* Timestamp */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-1">Data/Hora</div>
                  <div className="text-sm font-mono">
                    {formatTimestamp(selectedEntry.createdAt)}
                  </div>
                </div>
                
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-1">Ação</div>
                  <Badge className={getActionColor(selectedEntry.action)}>
                    {getActionLabel(selectedEntry.action)}
                  </Badge>
                </div>
                
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-1">Tipo</div>
                  <Badge variant="outline">
                    {getObjectTypeLabel(selectedEntry.objectType)}
                  </Badge>
                </div>
              </div>

              {/* Actor Info */}
              <div>
                <div className="text-sm font-medium text-muted-foreground mb-2">Usuário</div>
                <Card className="p-4">
                  <div className="flex items-center space-x-3">
                    <User className="h-8 w-8 text-muted-foreground" />
                    <div>
                      <div className="font-medium">
                        {selectedEntry.actorName || 'Usuário Sistema'}
                      </div>
                      {selectedEntry.actorEmail && (
                        <div className="text-sm text-muted-foreground">
                          {selectedEntry.actorEmail}
                        </div>
                      )}
                      <div className="text-xs text-muted-foreground font-mono mt-1">
                        ID: {selectedEntry.actorId}
                      </div>
                    </div>
                  </div>
                </Card>
              </div>

              {/* Object Details */}
              {selectedEntry.objectDetails && (
                <div>
                  <div className="text-sm font-medium text-muted-foreground mb-2">
                    Detalhes do Objeto
                  </div>
                  <Card className="p-4">
                    <div className="space-y-2">
                      {selectedEntry.objectDetails.name && (
                        <div>
                          <span className="text-sm font-medium">Nome: </span>
                          <span className="text-sm">{selectedEntry.objectDetails.name}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.title && (
                        <div>
                          <span className="text-sm font-medium">Título: </span>
                          <span className="text-sm">{selectedEntry.objectDetails.title}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.type && (
                        <div>
                          <span className="text-sm font-medium">Tipo: </span>
                          <span className="text-sm">{selectedEntry.objectDetails.type}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.username && (
                        <div>
                          <span className="text-sm font-medium">Username: </span>
                          <span className="text-sm">{selectedEntry.objectDetails.username}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.email && (
                        <div>
                          <span className="text-sm font-medium">Email: </span>
                          <span className="text-sm">{selectedEntry.objectDetails.email}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.value && (
                        <div>
                          <span className="text-sm font-medium">Valor: </span>
                          <span className="text-sm font-mono">{selectedEntry.objectDetails.value}</span>
                        </div>
                      )}
                      {selectedEntry.objectDetails.role && (
                        <div>
                          <span className="text-sm font-medium">Papel: </span>
                          <Badge variant="outline">{selectedEntry.objectDetails.role}</Badge>
                        </div>
                      )}
                      {selectedEntry.objectDetails.severity && (
                        <div>
                          <span className="text-sm font-medium">Severidade: </span>
                          <Badge variant="outline">{selectedEntry.objectDetails.severity}</Badge>
                        </div>
                      )}
                      {selectedEntry.objectDetails.status && (
                        <div>
                          <span className="text-sm font-medium">Status: </span>
                          <Badge variant="outline">{selectedEntry.objectDetails.status}</Badge>
                        </div>
                      )}
                      {selectedEntry.objectId && (
                        <div>
                          <span className="text-sm font-medium">ID do Objeto: </span>
                          <span className="text-xs font-mono text-muted-foreground">
                            {selectedEntry.objectId}
                          </span>
                        </div>
                      )}
                    </div>
                  </Card>
                </div>
              )}

              {/* Before/After State */}
              {(selectedEntry.before || selectedEntry.after) && (
                <div className="grid grid-cols-2 gap-4">
                  {selectedEntry.before && (
                    <div>
                      <div className="text-sm font-medium text-muted-foreground mb-2">
                        Estado Anterior
                      </div>
                      <Card className="p-4">
                        <pre className="text-xs overflow-auto max-h-60 bg-muted/50 p-3 rounded">
                          {JSON.stringify(selectedEntry.before, null, 2)}
                        </pre>
                      </Card>
                    </div>
                  )}
                  
                  {selectedEntry.after && (
                    <div>
                      <div className="text-sm font-medium text-muted-foreground mb-2">
                        Estado Posterior
                      </div>
                      <Card className="p-4">
                        <pre className="text-xs overflow-auto max-h-60 bg-muted/50 p-3 rounded">
                          {JSON.stringify(selectedEntry.after, null, 2)}
                        </pre>
                      </Card>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
