import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
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
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { 
  Search, 
  Server, 
  Globe, 
  Router,
  Monitor,
  Filter,
  Eye,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Minus,
  Package,
  Shield,
  Settings
} from "lucide-react";
import { Host, Threat, HostRiskHistory } from "@shared/schema";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';

// Helper function to get risk score color and label based on CVSS intervals
function getRiskScoreInfo(score: number) {
  if (score >= 90) return { 
    color: 'rgb(239, 68, 68)', // red-500
    bgColor: 'bg-red-500/10', 
    borderColor: 'border-red-500/30',
    label: 'CRÍTICO',
    textColor: 'text-red-500'
  };
  if (score >= 70) return { 
    color: 'rgb(249, 115, 22)', // orange-500
    bgColor: 'bg-orange-500/10', 
    borderColor: 'border-orange-500/30',
    label: 'ALTO',
    textColor: 'text-orange-500'
  };
  if (score >= 40) return { 
    color: 'rgb(234, 179, 8)', // yellow-500
    bgColor: 'bg-yellow-500/10', 
    borderColor: 'border-yellow-500/30',
    label: 'MÉDIO',
    textColor: 'text-yellow-500'
  };
  if (score >= 10) return { 
    color: 'rgb(34, 197, 94)', // green-500
    bgColor: 'bg-green-500/10', 
    borderColor: 'border-green-500/30',
    label: 'BAIXO',
    textColor: 'text-green-500'
  };
  return { 
    color: 'rgb(148, 163, 184)', // slate-400
    bgColor: 'bg-slate-500/10', 
    borderColor: 'border-slate-500/30',
    label: 'MÍNIMO',
    textColor: 'text-slate-400'
  };
}

// Risk Score Display Component
function RiskScoreDisplay({ host }: { host: Host }) {
  const riskInfo = getRiskScoreInfo(host.riskScore || 0);
  
  return (
    <div className={`p-6 rounded-lg border ${riskInfo.bgColor} ${riskInfo.borderColor}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium text-muted-foreground mb-1">Risk Score</div>
          <div className={`text-4xl font-bold ${riskInfo.textColor}`} data-testid="text-risk-score">
            {host.riskScore || 0}
          </div>
          <div className={`text-xs font-semibold mt-1 ${riskInfo.textColor}`}>
            {riskInfo.label}
          </div>
        </div>
        <div className="text-right">
          <div className="text-sm font-medium text-muted-foreground mb-1">Raw Score</div>
          <div className="text-2xl font-semibold" data-testid="text-raw-score">
            {host.rawScore || 0}
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            CVSS Total
          </div>
        </div>
      </div>
    </div>
  );
}

// Risk History Chart Component
function RiskHistoryChart({ hostId }: { hostId: string }) {
  const { data: history = [], isLoading } = useQuery<HostRiskHistory[]>({
    queryKey: ['/api/hosts', hostId, 'risk-history'],
    queryFn: async () => {
      const res = await fetch(`/api/hosts/${hostId}/risk-history?limit=30`);
      if (!res.ok) throw new Error('Failed to fetch risk history');
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 border rounded-lg bg-muted/30 animate-pulse">
        <div className="text-sm text-muted-foreground text-center">
          Carregando histórico...
        </div>
      </div>
    );
  }

  if (!history || history.length === 0) {
    return (
      <div className="p-6 border rounded-lg bg-muted/30">
        <div className="text-sm text-muted-foreground text-center">
          Histórico de Risk Score não disponível
        </div>
      </div>
    );
  }

  // Reverse to show oldest to newest
  const chartData = [...history].reverse().map(h => ({
    date: new Date(h.recordedAt).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }),
    riskScore: h.riskScore,
    rawScore: h.rawScore,
    fullDate: new Date(h.recordedAt).toLocaleString('pt-BR'),
  }));

  // Calculate trend
  const trend = history.length >= 2 
    ? history[0].riskScore - history[1].riskScore 
    : 0;

  const TrendIcon = trend > 0 ? TrendingUp : trend < 0 ? TrendingDown : Minus;
  const trendColor = trend > 0 ? 'text-red-500' : trend < 0 ? 'text-green-500' : 'text-muted-foreground';

  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold">Tendência de Risk Score</h3>
        <div className={`flex items-center gap-1 text-sm ${trendColor}`}>
          <TrendIcon className="h-4 w-4" />
          {trend > 0 ? `+${trend}` : trend}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={getRiskScoreInfo(history[0]?.riskScore || 0).color} stopOpacity={0.3}/>
              <stop offset="95%" stopColor={getRiskScoreInfo(history[0]?.riskScore || 0).color} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis 
            dataKey="date" 
            tick={{ fontSize: 10 }}
            stroke="currentColor"
            className="text-muted-foreground"
          />
          <YAxis 
            domain={[0, 100]}
            tick={{ fontSize: 10 }}
            stroke="currentColor"
            className="text-muted-foreground"
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: 'hsl(var(--background))', 
              border: '1px solid hsl(var(--border))',
              borderRadius: '6px'
            }}
            labelStyle={{ color: 'hsl(var(--foreground))' }}
            formatter={(value: any, name: string) => [
              value,
              name === 'riskScore' ? 'Risk Score' : 'Raw Score'
            ]}
          />
          <Area 
            type="monotone" 
            dataKey="riskScore" 
            stroke={getRiskScoreInfo(history[0]?.riskScore || 0).color}
            strokeWidth={2}
            fill="url(#colorRisk)" 
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// AD Security Test Results Component
interface AdSecurityTestResult {
  id: string;
  jobId: string;
  hostId: string;
  testId: string;
  testName: string;
  category: string;
  severityHint: 'low' | 'medium' | 'high' | 'critical';
  status: 'pass' | 'fail' | 'error' | 'skipped';
  evidence: Record<string, any>;
  executedAt: string;
}

function ADSecurityTests({ hostId }: { hostId: string }) {
  const [selectedTest, setSelectedTest] = useState<AdSecurityTestResult | null>(null);
  
  const { data: testResults = [], isLoading } = useQuery<AdSecurityTestResult[]>({
    queryKey: ['/api/hosts', hostId, 'ad-tests'],
    queryFn: async () => {
      const res = await fetch(`/api/hosts/${hostId}/ad-tests`);
      if (!res.ok) throw new Error('Failed to fetch AD test results');
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 border rounded-lg bg-muted/30 animate-pulse">
        <div className="text-sm text-muted-foreground text-center">
          Carregando testes AD Security...
        </div>
      </div>
    );
  }

  if (!testResults || testResults.length === 0) {
    return null; // Don't show section if no AD tests available
  }

  // Group tests by category
  const categories = {
    configuracoes_criticas: 'Configurações Críticas',
    gerenciamento_contas: 'Gerenciamento de Contas',
    kerberos_delegacao: 'Kerberos e Delegação',
    compartilhamentos_gpos: 'Compartilhamentos e GPOs',
    politicas_configuracao: 'Políticas e Configuração',
    contas_inativas: 'Contas Inativas',
  } as const;

  const testsByCategory = testResults.reduce((acc, test) => {
    if (!acc[test.category]) {
      acc[test.category] = [];
    }
    acc[test.category].push(test);
    return acc;
  }, {} as Record<string, AdSecurityTestResult[]>);

  // Get status badge styling
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pass':
        return { className: 'bg-green-500/10 text-green-500 border-green-500/30', label: 'PASSOU' };
      case 'fail':
        return { className: 'bg-red-500/10 text-red-500 border-red-500/30', label: 'FALHOU' };
      case 'error':
        return { className: 'bg-orange-500/10 text-orange-500 border-orange-500/30', label: 'ERRO' };
      case 'skipped':
        return { className: 'bg-slate-500/10 text-slate-400 border-slate-500/30', label: 'PULADO' };
      default:
        return { className: 'bg-slate-500/10 text-slate-400 border-slate-500/30', label: status.toUpperCase() };
    }
  };

  // Calculate summary stats
  const stats = testResults.reduce((acc, test) => {
    acc[test.status] = (acc[test.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold">Testes AD Security</h3>
        <div className="flex items-center gap-2 text-xs">
          {stats.pass > 0 && (
            <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/30">
              {stats.pass} passou
            </Badge>
          )}
          {stats.fail > 0 && (
            <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/30">
              {stats.fail} falhou
            </Badge>
          )}
          {stats.error > 0 && (
            <Badge variant="outline" className="bg-orange-500/10 text-orange-500 border-orange-500/30">
              {stats.error} erro
            </Badge>
          )}
          {stats.skipped > 0 && (
            <Badge variant="outline" className="bg-slate-500/10 text-slate-400 border-slate-500/30">
              {stats.skipped} pulado
            </Badge>
          )}
        </div>
      </div>

      <div className="space-y-4">
        {Object.entries(testsByCategory).map(([categoryKey, tests]) => {
          const categoryName = categories[categoryKey as keyof typeof categories] || categoryKey;
          
          return (
            <div key={categoryKey} className="border-t pt-3">
              <div className="text-xs font-medium text-muted-foreground mb-2">
                {categoryName}
              </div>
              <div className="space-y-1">
                {tests.map((test) => {
                  const statusBadge = getStatusBadge(test.status);
                  return (
                    <div
                      key={test.id}
                      className="flex items-center justify-between p-2 rounded hover:bg-muted/50 text-xs"
                      data-testid={`test-result-${test.testId}`}
                    >
                      <span className="text-foreground/90 flex-1">{test.testName}</span>
                      <Badge
                        variant="outline"
                        className={`ml-2 cursor-pointer hover:opacity-80 ${statusBadge.className}`}
                        onClick={() => setSelectedTest(test)}
                        data-testid={`badge-status-${test.testId}`}
                      >
                        {statusBadge.label}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="text-xs text-muted-foreground mt-3 pt-3 border-t">
        Última execução: {new Date(testResults[0]?.executedAt).toLocaleString('pt-BR')}
      </div>

      {/* Evidence Dialog */}
      <Dialog open={!!selectedTest} onOpenChange={() => setSelectedTest(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-lg font-bold">
              {selectedTest?.testName}
            </DialogTitle>
          </DialogHeader>
          {selectedTest && (
            <div className="space-y-4">
              {/* Status */}
              <div>
                <label className="text-xs font-medium text-muted-foreground">Status</label>
                <div className="mt-1">
                  <Badge
                    variant="outline"
                    className={getStatusBadge(selectedTest.status).className}
                  >
                    {getStatusBadge(selectedTest.status).label}
                  </Badge>
                </div>
              </div>

              {/* Comando PowerShell */}
              {selectedTest.evidence?.command && (
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Comando PowerShell Executado
                  </label>
                  <pre className="mt-1 p-3 bg-muted rounded-md text-xs overflow-x-auto font-mono">
                    {selectedTest.evidence.command}
                  </pre>
                </div>
              )}

              {/* Output (stdout) */}
              {selectedTest.evidence?.stdout && (
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Output (stdout)
                  </label>
                  <pre className="mt-1 p-3 bg-muted rounded-md text-xs overflow-x-auto max-h-60 font-mono">
                    {selectedTest.evidence.stdout}
                  </pre>
                </div>
              )}

              {/* Errors (stderr) */}
              {selectedTest.evidence?.stderr && selectedTest.evidence.stderr.length > 0 && (
                <div>
                  <label className="text-xs font-medium text-muted-foreground text-orange-500">
                    Errors (stderr)
                  </label>
                  <pre className="mt-1 p-3 bg-orange-500/10 border border-orange-500/30 rounded-md text-xs overflow-x-auto max-h-40 font-mono text-orange-500">
                    {selectedTest.evidence.stderr}
                  </pre>
                </div>
              )}

              {/* Exit Code */}
              {selectedTest.evidence?.exitCode !== undefined && (
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Exit Code</label>
                  <div className="mt-1 text-sm font-mono">
                    {selectedTest.evidence.exitCode}
                  </div>
                </div>
              )}

              {/* Test ID */}
              <div className="pt-3 border-t">
                <label className="text-xs font-medium text-muted-foreground">Test ID</label>
                <div className="mt-1 text-xs font-mono">{selectedTest.testId}</div>
              </div>

              {/* Execution Time */}
              <div>
                <label className="text-xs font-medium text-muted-foreground">
                  Data de Execução
                </label>
                <div className="mt-1 text-xs">
                  {new Date(selectedTest.executedAt).toLocaleString('pt-BR')}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Host Enrichment Data Component
interface HostEnrichment {
  id: string;
  hostId: string;
  jobId: string;
  protocol: 'wmi' | 'ssh' | 'snmp';
  success: boolean;
  osVersion: string | null;
  osBuild: string | null;
  installedApps: Array<{ name: string; version: string; vendor?: string }> | null;
  patches: string[] | null;
  services: Array<{ name: string; displayName?: string; startType?: string; status?: string; description?: string }> | null;
  collectedAt: string;
  errorMessage: string | null;
}

function HostEnrichmentTabs({ hostId }: { hostId: string }) {
  const { data: enrichment, isLoading } = useQuery<HostEnrichment | null>({
    queryKey: ['/api/hosts', hostId, 'enrichments'],
    queryFn: async () => {
      const res = await fetch(`/api/hosts/${hostId}/enrichments`);
      if (!res.ok) throw new Error('Failed to fetch enrichment data');
      return res.json();
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 border rounded-lg bg-muted/30 animate-pulse">
        <div className="text-sm text-muted-foreground text-center">
          Carregando dados de enriquecimento...
        </div>
      </div>
    );
  }

  if (!enrichment || !enrichment.success) {
    return null;
  }

  return (
    <div className="border rounded-lg p-4" data-testid="host-enrichment-tabs">
      <h3 className="text-sm font-semibold mb-4">Dados de Enriquecimento</h3>
      
      <Tabs defaultValue="general" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="general" className="text-xs">
            <Monitor className="w-3 h-3 mr-1.5" />
            Geral
          </TabsTrigger>
          <TabsTrigger value="apps" className="text-xs">
            <Package className="w-3 h-3 mr-1.5" />
            Programas ({enrichment.installedApps?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="patches" className="text-xs">
            <Shield className="w-3 h-3 mr-1.5" />
            Patches ({enrichment.patches?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="services" className="text-xs">
            <Settings className="w-3 h-3 mr-1.5" />
            Serviços ({enrichment.services?.length || 0})
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="general" className="mt-4 space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Sistema Operacional</label>
            <div className="text-sm mt-1 font-mono" data-testid="text-enrichment-os">
              {enrichment.osVersion || '—'}
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Build</label>
            <div className="text-sm mt-1 font-mono" data-testid="text-enrichment-build">
              {enrichment.osBuild || '—'}
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Protocolo</label>
            <div className="text-sm mt-1">
              <Badge variant="outline">{enrichment.protocol.toUpperCase()}</Badge>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Coletado em</label>
            <div className="text-xs mt-1 text-muted-foreground">
              {new Date(enrichment.collectedAt).toLocaleString('pt-BR')}
            </div>
          </div>
        </TabsContent>
        
        <TabsContent value="apps" className="mt-4">
          <div className="max-h-64 overflow-y-auto">
            {enrichment.installedApps && enrichment.installedApps.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Nome</TableHead>
                    <TableHead className="text-xs">Versão</TableHead>
                    <TableHead className="text-xs">Fabricante</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {enrichment.installedApps.map((app, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="text-xs font-medium">{app.name}</TableCell>
                      <TableCell className="text-xs font-mono">{app.version || '—'}</TableCell>
                      <TableCell className="text-xs">{app.vendor || '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-sm text-muted-foreground text-center py-8">
                Nenhum programa instalado detectado
              </div>
            )}
          </div>
        </TabsContent>
        
        <TabsContent value="patches" className="mt-4">
          <div className="max-h-64 overflow-y-auto">
            {enrichment.patches && enrichment.patches.length > 0 ? (
              <div className="grid grid-cols-2 gap-2">
                {enrichment.patches.map((patch, idx) => (
                  <Badge key={idx} variant="outline" className="justify-start font-mono text-xs">
                    {patch}
                  </Badge>
                ))}
              </div>
            ) : (
              <div className="text-sm text-muted-foreground text-center py-8">
                Nenhum patch detectado
              </div>
            )}
          </div>
        </TabsContent>
        
        <TabsContent value="services" className="mt-4">
          <div className="max-h-64 overflow-y-auto">
            {enrichment.services && enrichment.services.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Nome</TableHead>
                    <TableHead className="text-xs">Inicialização</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Descrição</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {enrichment.services.map((service, idx) => (
                    <TableRow key={idx}>
                      <TableCell className="text-xs font-medium" data-testid={`text-service-name-${idx}`}>
                        {service.displayName || service.name}
                      </TableCell>
                      <TableCell className="text-xs" data-testid={`text-service-starttype-${idx}`}>
                        {service.startType || '—'}
                      </TableCell>
                      <TableCell className="text-xs" data-testid={`text-service-status-${idx}`}>
                        <Badge 
                          variant="outline" 
                          className={
                            service.status === 'Running' ? 'bg-green-500/10 text-green-600 border-green-500/30' :
                            service.status === 'Stopped' ? 'bg-gray-500/10 text-gray-600 border-gray-500/30' :
                            service.status === 'Failed' ? 'bg-red-500/10 text-red-600 border-red-500/30' :
                            ''
                          }
                        >
                          {service.status || '—'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-xs truncate" data-testid={`text-service-description-${idx}`}>
                        {service.description || '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <div className="text-sm text-muted-foreground text-center py-8">
                Nenhum serviço detectado
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// Compact Threat Badges Component
function CompactThreatBadges({ threats, hostId }: { threats: Threat[], hostId: string }) {
  const [, setLocation] = useLocation();
  
  const threatCounts = useMemo(() => {
    return threats.reduce((counts, threat) => {
      counts[threat.severity] = (counts[threat.severity] || 0) + 1;
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>);
  }, [threats]);

  const handleClick = (severity: string) => {
    const params = new URLSearchParams();
    params.set('hostId', hostId);
    if (severity !== 'all') {
      params.set('severity', severity);
    }
    setLocation(`/threats?${params.toString()}`);
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-sm font-medium text-muted-foreground">Ameaças:</span>
      
      <Badge 
        variant="outline"
        className="bg-red-500/10 text-red-500 border-red-500/30 cursor-pointer hover:bg-red-500/20"
        onClick={() => handleClick('critical')}
        data-testid="badge-threats-critical"
      >
        <div className="w-2 h-2 bg-red-500 rounded-full mr-1.5"></div>
        Crítica: {threatCounts.critical}
      </Badge>
      
      <Badge 
        variant="outline"
        className="bg-orange-500/10 text-orange-500 border-orange-500/30 cursor-pointer hover:bg-orange-500/20"
        onClick={() => handleClick('high')}
        data-testid="badge-threats-high"
      >
        <div className="w-2 h-2 bg-orange-500 rounded-full mr-1.5"></div>
        Alta: {threatCounts.high}
      </Badge>
      
      <Badge 
        variant="outline"
        className="bg-yellow-500/10 text-yellow-500 border-yellow-500/30 cursor-pointer hover:bg-yellow-500/20"
        onClick={() => handleClick('medium')}
        data-testid="badge-threats-medium"
      >
        <div className="w-2 h-2 bg-yellow-500 rounded-full mr-1.5"></div>
        Média: {threatCounts.medium}
      </Badge>
      
      <Badge 
        variant="outline"
        className="bg-green-500/10 text-green-600 border-green-500/30 cursor-pointer hover:bg-green-500/20"
        onClick={() => handleClick('low')}
        data-testid="badge-threats-low"
      >
        <div className="w-2 h-2 bg-green-600 rounded-full mr-1.5"></div>
        Baixa: {threatCounts.low}
      </Badge>
    </div>
  );
}

// Threat Summary Component (OLD - will be replaced)
function ThreatSummarySection({ threats, hostId }: { threats: Threat[], hostId: string }) {
  const [, setLocation] = useLocation();
  
  const threatCounts = useMemo(() => {
    return threats.reduce((counts, threat) => {
      counts[threat.severity] = (counts[threat.severity] || 0) + 1;
      return counts;
    }, { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>);
  }, [threats]);

  const handleSeverityClick = (severity: string, count: number) => {
    const params = new URLSearchParams();
    params.set('hostId', hostId);
    if (severity !== 'all') {
      params.set('severity', severity);
    }
    setLocation(`/threats?${params.toString()}`);
  };

  return (
    <div className="pt-4 border-t">
      <label className="text-sm font-medium flex items-center gap-2 mb-3">
        <AlertTriangle className="h-4 w-4" />
        Resumo de Ameaças ({threats.length})
      </label>
      
      <div className="grid grid-cols-2 gap-3">
        {/* Crítica */}
        <div className="flex items-center justify-between p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span className="text-sm font-medium">Crítica</span>
          </div>
          <Badge 
            variant="destructive" 
            className="min-w-[2rem] justify-center cursor-pointer hover:bg-red-700"
            data-testid="text-threats-critical-count"
            onClick={() => handleSeverityClick('critical', threatCounts.critical)}
          >
            {threatCounts.critical}
          </Badge>
        </div>
        
        {/* Alta */}
        <div className="flex items-center justify-between p-3 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
            <span className="text-sm font-medium">Alta</span>
          </div>
          <Badge 
            variant="outline" 
            className="min-w-[2rem] justify-center bg-orange-500 text-white border-orange-500 cursor-pointer hover:bg-orange-700"
            data-testid="text-threats-high-count"
            onClick={() => handleSeverityClick('high', threatCounts.high)}
          >
            {threatCounts.high}
          </Badge>
        </div>
        
        {/* Média */}
        <div className="flex items-center justify-between p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <span className="text-sm font-medium">Média</span>
          </div>
          <Badge 
            variant="outline" 
            className="min-w-[2rem] justify-center bg-yellow-500 text-white border-yellow-500 cursor-pointer hover:bg-yellow-700"
            data-testid="text-threats-medium-count"
            onClick={() => handleSeverityClick('medium', threatCounts.medium)}
          >
            {threatCounts.medium}
          </Badge>
        </div>
        
        {/* Baixa */}
        <div className="flex items-center justify-between p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-sm font-medium">Baixa</span>
          </div>
          <Badge 
            variant="outline" 
            className="min-w-[2rem] justify-center bg-green-600 text-white border-green-600 cursor-pointer hover:bg-green-800"
            data-testid="text-threats-low-count"
            onClick={() => handleSeverityClick('low', threatCounts.low)}
          >
            {threatCounts.low}
          </Badge>
        </div>
      </div>
    </div>
  );
}

type HostWithThreatCounts = Host & {
  threatCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
};

export default function Hosts() {
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [familyFilter, setFamilyFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<string>("updatedAt");
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Build query params for filtering
  const queryParams = new URLSearchParams();
  if (typeFilter !== "all") queryParams.set("type", typeFilter);
  if (familyFilter !== "all") queryParams.set("family", familyFilter);
  if (searchTerm) queryParams.set("search", searchTerm);
  if (sortBy) queryParams.set("sortBy", sortBy);
  
  const queryString = queryParams.toString();
  const apiUrl = queryString ? `/api/hosts?${queryString}` : "/api/hosts";

  const { data: hosts = [], isLoading, error } = useQuery<HostWithThreatCounts[]>({
    queryKey: ['/api/hosts', { type: typeFilter, family: familyFilter, search: searchTerm, sortBy }],
  });

  // Query for threats associated with the selected host
  const { data: hostThreats = [] } = useQuery<Threat[]>({
    queryKey: ['/api/threats', { hostId: selectedHost?.id }],
    enabled: !!selectedHost,
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


  const handleViewHost = (host: Host) => {
    setSelectedHost(host);
  };


  const getHostIcon = (type: string) => {
    switch (type) {
      case 'server':
        return Server;
      case 'desktop':
        return Monitor;
      case 'router':
      case 'switch':
      case 'firewall':
        return Router;
      case 'domain':
        return Globe;
      case 'other':
      default:
        return Server;
    }
  };

  const getHostTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'server':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
      case 'desktop':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      case 'router':
      case 'switch':
      case 'firewall':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300';
      case 'domain':
        return 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-300';
      case 'other':
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300';
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <main className="flex-1 overflow-hidden">
        <TopBar 
          title="Gestão de Ativos"
          subtitle="Visualize e gerencie ativos descobertos pelos scans de segurança"
        />
        
        <div className="p-6 space-y-6 overflow-auto h-[calc(100%-4rem)]">
          {/* Filters and Search */}
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
              <Input
                type="text"
                placeholder="Buscar ativos por nome, IP ou alias..."
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
                  <SelectItem value="desktop">Desktop</SelectItem>
                  <SelectItem value="firewall">Firewall</SelectItem>
                  <SelectItem value="switch">Switch</SelectItem>
                  <SelectItem value="router">Router</SelectItem>
                  <SelectItem value="domain">Domínio</SelectItem>
                  <SelectItem value="other">Outro</SelectItem>
                </SelectContent>
              </Select>

              <Select value={familyFilter} onValueChange={setFamilyFilter}>
                <SelectTrigger className="w-[160px]" data-testid="select-family-filter">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Família" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Todas as famílias</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="windows_server">Windows Server</SelectItem>
                  <SelectItem value="windows_desktop">Windows Desktop</SelectItem>
                  <SelectItem value="fortios">FortiOS</SelectItem>
                  <SelectItem value="network_os">Network OS</SelectItem>
                  <SelectItem value="other">Outra</SelectItem>
                </SelectContent>
              </Select>

              <Select value={sortBy} onValueChange={setSortBy}>
                <SelectTrigger className="w-[180px]" data-testid="select-sort-by">
                  <SelectValue placeholder="Ordenar por" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="riskScore">Escore de Risco</SelectItem>
                  <SelectItem value="rawScore">Pontuação Total</SelectItem>
                  <SelectItem value="updatedAt">Última Atualização</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Assets Count */}
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              {filteredHosts.length} ativos encontrados
            </div>
          </div>

          {/* Assets Table */}
          <Card>
            <CardHeader>
              <CardTitle>Ativos Descobertos</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-4">
                  <p className="text-muted-foreground">Carregando ativos...</p>
                </div>
              ) : error ? (
                <div className="text-center py-8">
                  <p className="text-destructive mb-2">Erro ao carregar ativos</p>
                  <p className="text-sm text-muted-foreground">
                    {error instanceof Error ? error.message : 'Erro desconhecido'}
                  </p>
                </div>
              ) : filteredHosts.length === 0 ? (
                <div className="text-center py-8">
                  <div className="text-muted-foreground mb-4">
                    {searchTerm || typeFilter !== "all" || familyFilter !== "all" 
                      ? 'Nenhum ativo encontrado com os filtros aplicados' 
                      : 'Nenhum ativo descoberto ainda'
                    }
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {searchTerm || typeFilter !== "all" || familyFilter !== "all"
                      ? 'Tente ajustar os filtros de busca'
                      : 'Execute scans de Attack Surface para descobrir ativos automaticamente'
                    }
                  </div>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Host</TableHead>
                      <TableHead>Categoria</TableHead>
                      <TableHead>Tipo</TableHead>
                      <TableHead>Escore de Risco</TableHead>
                      <TableHead>Ameaças</TableHead>
                      <TableHead>IPs</TableHead>
                      <TableHead>Sistema Operacional</TableHead>
                      <TableHead>Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredHosts.map((host) => {
                      const Icon = getHostIcon(host.type);
                      const totalThreats = (host.threatCounts?.critical || 0) + 
                                         (host.threatCounts?.high || 0) + 
                                         (host.threatCounts?.medium || 0) + 
                                         (host.threatCounts?.low || 0);
                      
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
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant="outline" 
                              className="bg-green-500/10 text-green-600 border-green-500/20"
                            >
                              Host
                            </Badge>
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
                            <div className="flex flex-col gap-1">
                              <div className="text-lg font-bold" data-testid={`text-risk-score-${host.id}`}>
                                {host.riskScore || 0}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Pontos: {host.rawScore || 0}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            {totalThreats > 0 ? (
                              <div className="flex gap-1.5" data-testid={`threats-badges-${host.id}`}>
                                {host.threatCounts.critical > 0 && (
                                  <Badge 
                                    variant="destructive" 
                                    className="min-w-[28px] h-6 justify-center bg-red-500 hover:bg-red-600"
                                  >
                                    {host.threatCounts.critical}
                                  </Badge>
                                )}
                                {host.threatCounts.high > 0 && (
                                  <Badge 
                                    className="min-w-[28px] h-6 justify-center bg-orange-500 text-white hover:bg-orange-600"
                                  >
                                    {host.threatCounts.high}
                                  </Badge>
                                )}
                                {host.threatCounts.medium > 0 && (
                                  <Badge 
                                    className="min-w-[28px] h-6 justify-center bg-yellow-500 text-white hover:bg-yellow-600"
                                  >
                                    {host.threatCounts.medium}
                                  </Badge>
                                )}
                                {host.threatCounts.low > 0 && (
                                  <Badge 
                                    className="min-w-[28px] h-6 justify-center bg-green-600 text-white hover:bg-green-700"
                                  >
                                    {host.threatCounts.low}
                                  </Badge>
                                )}
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
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
                            <div className="flex space-x-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleViewHost(host)}
                                data-testid={`button-view-${host.id}`}
                              >
                                <Eye className="h-4 w-4" />
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
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl font-bold">{selectedHost?.name}</DialogTitle>
          </DialogHeader>
          {selectedHost && (
            <div className="space-y-6">
              {/* Risk Score Section - Highlighted at the top */}
              <RiskScoreDisplay host={selectedHost} />
              
              {/* Risk History Chart */}
              <RiskHistoryChart hostId={selectedHost.id} />
              
              {/* AD Security Tests */}
              <ADSecurityTests hostId={selectedHost.id} />
              
              {/* Host Enrichment Data */}
              <HostEnrichmentTabs hostId={selectedHost.id} />
              
              {/* Compact Threat Badges */}
              {hostThreats && Array.isArray(hostThreats) && hostThreats.length > 0 && (
                <div className="pt-4 border-t">
                  <CompactThreatBadges threats={hostThreats} hostId={selectedHost.id} />
                </div>
              )}
              
              {/* Host Information */}
              <div className="pt-4 border-t space-y-4">
                <h3 className="text-sm font-semibold">Informações do Host</h3>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Tipo</label>
                    <div className="text-sm mt-1">{selectedHost.type}</div>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Família</label>
                    <div className="text-sm mt-1">{selectedHost.family || '—'}</div>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Sistema Operacional</label>
                    <div className="text-sm mt-1">{selectedHost.operatingSystem || '—'}</div>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Descoberto em</label>
                    <div className="text-sm mt-1">
                      {new Date(selectedHost.discoveredAt).toLocaleDateString('pt-BR')}
                    </div>
                  </div>
                </div>
                
                {selectedHost.description && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Descrição</label>
                    <div className="text-sm mt-1">{selectedHost.description}</div>
                  </div>
                )}
                
                {selectedHost.ips && selectedHost.ips.length > 0 && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Endereços IP</label>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {selectedHost.ips.map((ip, index) => (
                        <Badge key={index} variant="outline" className="font-mono text-xs">
                          {ip}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                
                {selectedHost.aliases && selectedHost.aliases.length > 0 && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Aliases</label>
                    <div className="flex flex-wrap gap-2 mt-1">
                      {selectedHost.aliases.map((alias, index) => (
                        <Badge key={index} variant="secondary" className="text-xs">
                          {alias}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}