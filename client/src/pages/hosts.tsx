import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { 
  Search, 
  Edit, 
  Server, 
  Globe, 
  Shield, 
  Router,
  Smartphone,
  Monitor,
  HardDrive,
  Filter,
  Eye
} from "lucide-react";
import { Host } from "@shared/schema";

export default function Hosts() {
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [familyFilter, setFamilyFilter] = useState<string>("all");
  const [editingHost, setEditingHost] = useState<Host | null>(null);
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Build query params for filtering
  const queryParams = new URLSearchParams();
  if (typeFilter !== "all") queryParams.set("type", typeFilter);
  if (familyFilter !== "all") queryParams.set("family", familyFilter);
  if (searchTerm) queryParams.set("search", searchTerm);
  
  const queryString = queryParams.toString();
  const apiUrl = queryString ? `/api/hosts?${queryString}` : "/api/hosts";

  const { data: hosts = [], isLoading, error } = useQuery<Host[]>({
    queryKey: ['/api/hosts', { type: typeFilter, family: familyFilter, search: searchTerm }],
  });

  const updateHostMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<Host> }) => {
      return await apiRequest('PATCH', `/api/hosts/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Host atualizado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/hosts'] });
      setEditingHost(null);
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
        description: "Falha ao atualizar host",
        variant: "destructive",
      });
    },
  });

  const filteredHosts = hosts.filter(host => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    return (
      host.name.toLowerCase().includes(searchLower) ||
      host.ips?.some(ip => ip.includes(searchLower)) ||
      host.aliases?.some(alias => alias.toLowerCase().includes(searchLower)) ||
      (host.description && host.description.toLowerCase().includes(searchLower))
    );
  });

  const handleEditHost = (host: Host) => {
    setEditingHost(host);
  };

  const handleViewHost = (host: Host) => {
    setSelectedHost(host);
  };

  const handleUpdateHost = async (data: { name: string; description: string; aliases: string[] }) => {
    if (!editingHost) return;
    
    updateHostMutation.mutate({
      id: editingHost.id,
      data
    });
  };

  const getHostIcon = (type: string) => {
    switch (type) {
      case 'server':
        return Server;
      case 'workstation':
      case 'windows_desktop':
        return Monitor;
      case 'network_device':
      case 'router':
      case 'switch':
      case 'firewall':
        return Router;
      case 'mobile':
        return Smartphone;
      case 'domain':
        return Globe;
      case 'domain_controller':
        return Shield;
      case 'storage':
        return HardDrive;
      default:
        return Server;
    }
  };

  const getHostTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'server':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
      case 'workstation':
      case 'windows_desktop':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      case 'network_device':
      case 'router':
      case 'switch':
      case 'firewall':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300';
      case 'mobile':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300';
      case 'domain':
        return 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-300';
      case 'domain_controller':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300';
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar 
          title="Gestão de Hosts"
          subtitle="Visualize e gerencie hosts descobertos pelos scans de segurança"
        />
        
        <div className="p-6 space-y-6 overflow-auto h-[calc(100%-4rem)]">
          {/* Filters and Search */}
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
              <Input
                type="text"
                placeholder="Buscar hosts por nome, IP ou alias..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
                data-testid="input-host-search"
              />
            </div>
            
            <div className="flex gap-2">
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[160px]" data-testid="select-type-filter">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Tipo" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todos os tipos</SelectItem>
                  <SelectItem value="server">Servidor</SelectItem>
                  <SelectItem value="workstation">Workstation</SelectItem>
                  <SelectItem value="network_device">Dispositivo de rede</SelectItem>
                  <SelectItem value="mobile">Mobile</SelectItem>
                  <SelectItem value="domain">Domínio</SelectItem>
                  <SelectItem value="domain_controller">Domain Controller</SelectItem>
                  <SelectItem value="router">Router</SelectItem>
                  <SelectItem value="switch">Switch</SelectItem>
                  <SelectItem value="firewall">Firewall</SelectItem>
                  <SelectItem value="windows_desktop">Windows Desktop</SelectItem>
                  <SelectItem value="storage">Storage</SelectItem>
                </SelectContent>
              </Select>

              <Select value={familyFilter} onValueChange={setFamilyFilter}>
                <SelectTrigger className="w-[160px]" data-testid="select-family-filter">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Família" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todas as famílias</SelectItem>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="network_os">Network OS</SelectItem>
                  <SelectItem value="fortios">FortiOS</SelectItem>
                  <SelectItem value="unknown">Desconhecida</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Hosts Count */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              {filteredHosts.length} hosts encontrados
            </div>
          </div>

          {/* Hosts Table */}
          <Card>
            <CardHeader>
              <CardTitle>Hosts Descobertos</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-4">
                  <p className="text-muted-foreground">Carregando hosts...</p>
                </div>
              ) : error ? (
                <div className="text-center py-8">
                  <p className="text-destructive mb-2">Erro ao carregar hosts</p>
                  <p className="text-sm text-muted-foreground">
                    {error instanceof Error ? error.message : 'Erro desconhecido'}
                  </p>
                </div>
              ) : filteredHosts.length === 0 ? (
                <div className="text-center py-8">
                  <div className="text-muted-foreground mb-4">
                    {searchTerm || typeFilter !== "all" || familyFilter !== "all" 
                      ? 'Nenhum host encontrado com os filtros aplicados' 
                      : 'Nenhum host descoberto ainda'
                    }
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {searchTerm || typeFilter !== "all" || familyFilter !== "all"
                      ? 'Tente ajustar os filtros de busca'
                      : 'Execute scans de Attack Surface para descobrir hosts automaticamente'
                    }
                  </div>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Host</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>IPs</TableHead>
                      <TableHead>Sistema Operacional</TableHead>
                      <TableHead>Sistema</TableHead>
                      <TableHead>Descoberto em</TableHead>
                      <TableHead>Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredHosts.map((host) => {
                      const Icon = getHostIcon(host.type);
                      return (
                        <TableRow key={host.id} data-testid={`host-row-${host.id}`}>
                          <TableCell className="font-medium">
                            <div className="flex items-center space-x-3">
                              <Icon className="h-4 w-4 text-muted-foreground" />
                              <div>
                                <div className="font-medium">{host.name}</div>
                                {host.description && (
                                  <div className="text-xs text-muted-foreground">
                                    {host.description}
                                  </div>
                                )}
                                {host.aliases && host.aliases.length > 0 && (
                                  <div className="text-xs text-muted-foreground">
                                    Aliases: {host.aliases.join(', ')}
                                  </div>
                                )}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant="secondary" 
                              className={getHostTypeBadgeColor(host.type)}
                            >
                              {host.type.replace('_', ' ')}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="text-sm">
                              {host.ips && host.ips.length > 0 ? (
                                <div className="space-y-1">
                                  {host.ips.slice(0, 2).map((ip, index) => (
                                    <div key={index} className="font-mono text-xs bg-muted px-2 py-1 rounded">
                                      {ip}
                                    </div>
                                  ))}
                                  {host.ips.length > 2 && (
                                    <div className="text-xs text-muted-foreground">
                                      +{host.ips.length - 2} mais
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="text-sm">
                              {host.operatingSystem ? (
                                <div className="font-medium">{host.operatingSystem}</div>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="text-sm">
                              {host.family ? (
                                <div className="font-medium">{host.family}</div>
                              ) : (
                                <span className="text-muted-foreground">—</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(host.discoveredAt).toLocaleDateString('pt-BR', {
                              day: '2-digit',
                              month: '2-digit',
                              year: 'numeric',
                            })}
                          </TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleViewHost(host)}
                                data-testid={`button-view-${host.id}`}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleEditHost(host)}
                                data-testid={`button-edit-${host.id}`}
                              >
                                <Edit className="h-4 w-4" />
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

      {/* Host Details Dialog */}
      <Dialog open={!!selectedHost} onOpenChange={() => setSelectedHost(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Detalhes do Host</DialogTitle>
          </DialogHeader>
          {selectedHost && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium">Nome</label>
                  <div className="text-sm text-muted-foreground">{selectedHost.name}</div>
                </div>
                <div>
                  <label className="text-sm font-medium">Tipo</label>
                  <div className="text-sm text-muted-foreground">{selectedHost.type}</div>
                </div>
                <div>
                  <label className="text-sm font-medium">Família</label>
                  <div className="text-sm text-muted-foreground">{selectedHost.family || '—'}</div>
                </div>
                <div>
                  <label className="text-sm font-medium">Sistema Operacional</label>
                  <div className="text-sm text-muted-foreground">{selectedHost.operatingSystem || '—'}</div>
                </div>
              </div>
              
              {selectedHost.description && (
                <div>
                  <label className="text-sm font-medium">Descrição</label>
                  <div className="text-sm text-muted-foreground">{selectedHost.description}</div>
                </div>
              )}
              
              {selectedHost.ips && selectedHost.ips.length > 0 && (
                <div>
                  <label className="text-sm font-medium">Endereços IP</label>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {selectedHost.ips.map((ip, index) => (
                      <Badge key={index} variant="outline" className="font-mono">
                        {ip}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              
              
              {selectedHost.aliases && selectedHost.aliases.length > 0 && (
                <div>
                  <label className="text-sm font-medium">Aliases</label>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {selectedHost.aliases.map((alias, index) => (
                      <Badge key={index} variant="secondary">
                        {alias}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                <div>
                  <label className="text-sm font-medium">Descoberto em</label>
                  <div className="text-sm text-muted-foreground">
                    {new Date(selectedHost.discoveredAt).toLocaleString('pt-BR')}
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium">Última atualização</label>
                  <div className="text-sm text-muted-foreground">
                    {new Date(selectedHost.updatedAt).toLocaleString('pt-BR')}
                  </div>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Edit Host Dialog */}
      <Dialog open={!!editingHost} onOpenChange={() => setEditingHost(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Editar Host</DialogTitle>
          </DialogHeader>
          {editingHost && (
            <HostEditForm 
              host={editingHost}
              onSubmit={handleUpdateHost}
              onCancel={() => setEditingHost(null)}
              isLoading={updateHostMutation.isPending}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Simple inline edit form component
interface HostEditFormProps {
  host: Host;
  onSubmit: (data: { name: string; description: string; aliases: string[] }) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

function HostEditForm({ host, onSubmit, onCancel, isLoading = false }: HostEditFormProps) {
  const [name, setName] = useState(host.name);
  const [description, setDescription] = useState(host.description || "");
  const [aliasesText, setAliasesText] = useState(host.aliases?.join(', ') || "");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const aliases = aliasesText
      .split(',')
      .map(alias => alias.trim())
      .filter(alias => alias.length > 0);
    
    onSubmit({ name, description, aliases });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="text-sm font-medium">Nome</label>
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Nome do host"
          data-testid="input-host-name"
        />
      </div>
      
      <div>
        <label className="text-sm font-medium">Descrição</label>
        <Input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Descrição opcional"
          data-testid="input-host-description"
        />
      </div>
      
      <div>
        <label className="text-sm font-medium">Aliases (separados por vírgula)</label>
        <Input
          value={aliasesText}
          onChange={(e) => setAliasesText(e.target.value)}
          placeholder="alias1, alias2, alias3"
          data-testid="input-host-aliases"
        />
      </div>
      
      <div className="flex justify-end space-x-2">
        <Button type="button" variant="outline" onClick={onCancel} data-testid="button-cancel-edit">
          Cancelar
        </Button>
        <Button type="submit" disabled={isLoading} data-testid="button-save-host">
          {isLoading ? 'Salvando...' : 'Salvar'}
        </Button>
      </div>
    </form>
  );
}