import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Users, ClockArrowUp } from "lucide-react";
import { toast } from "@/hooks/use-toast";

interface DemoLead {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  company: string | null;
  cnpj: string | null;
  createdAt: string;
  demoExpiresAt: string | null;
  lastLogin: string | null;
}

function formatCnpj(cnpj: string | null): string {
  if (!cnpj) return '-';
  const d = cnpj.replace(/\D/g, '');
  if (d.length !== 14) return cnpj;
  return `${d.slice(0,2)}.${d.slice(2,5)}.${d.slice(5,8)}/${d.slice(8,12)}-${d.slice(12)}`;
}

function LeadStatus({ expiresAt }: { expiresAt: string | null }) {
  if (!expiresAt) return <Badge variant="secondary">-</Badge>;
  const expired = new Date() > new Date(expiresAt);
  return expired
    ? <Badge variant="destructive">Expirado</Badge>
    : <Badge variant="default" className="bg-green-600">Ativo</Badge>;
}

export default function DemoLeads() {
  const queryClient = useQueryClient();

  const { data: leads = [], isLoading, error } = useQuery<DemoLead[]>({
    queryKey: ["/api/demo/leads"],
    queryFn: async () => {
      const res = await apiRequest('GET', '/api/demo/leads');
      return res.json();
    },
  });

  const extendMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiRequest('POST', `/api/demo/leads/${id}/extend`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message ?? 'Erro ao prorrogar.');
      }
      return res.json();
    },
    onSuccess: (updated: DemoLead) => {
      queryClient.invalidateQueries({ queryKey: ["/api/demo/leads"] });
      const newExpiry = updated.demoExpiresAt
        ? new Date(updated.demoExpiresAt).toLocaleString('pt-BR')
        : '-';
      toast({ title: 'Acesso prorrogado', description: `Novo vencimento: ${newExpiry}` });
    },
    onError: (err: Error) => {
      toast({ title: 'Erro', description: err.message, variant: 'destructive' });
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
          <Users className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-foreground">Leads de Demonstração</h1>
          <p className="text-sm text-muted-foreground">
            Empresas que solicitaram acesso ao ambiente de demonstração
          </p>
        </div>
        <div className="ml-auto">
          <span className="text-2xl font-bold text-foreground">{leads.length}</span>
          <span className="text-sm text-muted-foreground ml-1">leads</span>
        </div>
      </div>

      {isLoading && (
        <div className="text-center py-12 text-muted-foreground">Carregando...</div>
      )}

      {error && (
        <div className="text-center py-12 text-destructive">
          Acesso negado. Esta página é exclusiva para admin@samureye.local.
        </div>
      )}

      {!isLoading && !error && (
        <div className="border rounded-lg overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nome</TableHead>
                <TableHead>Empresa</TableHead>
                <TableHead>CNPJ</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Cadastro</TableHead>
                <TableHead>Expira em</TableHead>
                <TableHead>Status</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {leads.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                    Nenhum lead registrado ainda.
                  </TableCell>
                </TableRow>
              )}
              {leads.map((lead) => (
                <TableRow key={lead.id}>
                  <TableCell className="font-medium">
                    {lead.firstName} {lead.lastName}
                  </TableCell>
                  <TableCell>{lead.company ?? '-'}</TableCell>
                  <TableCell className="font-mono text-sm">{formatCnpj(lead.cnpj)}</TableCell>
                  <TableCell>{lead.email}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(lead.createdAt).toLocaleString('pt-BR')}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {lead.demoExpiresAt
                      ? new Date(lead.demoExpiresAt).toLocaleString('pt-BR')
                      : '-'}
                  </TableCell>
                  <TableCell>
                    <LeadStatus expiresAt={lead.demoExpiresAt} />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="gap-1.5 text-muted-foreground hover:text-foreground"
                      disabled={extendMutation.isPending}
                      onClick={() => extendMutation.mutate(lead.id)}
                      title="Prorrogar 72h"
                    >
                      <ClockArrowUp className="w-4 h-4" />
                      Prorrogar
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
