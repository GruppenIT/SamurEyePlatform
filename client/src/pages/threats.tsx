import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useToast } from "@/hooks/use-toast";
import { useWebSocket } from "@/lib/websocket";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Search,
  AlertTriangle,
  Eye,
  CheckCircle,
  Clock,
  Shield,
  Download,
  ChevronDown,
  ChevronRight,
  Wrench,
  AlertCircle,
  ListChecks,
  ClipboardList,
} from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { AssociateToPlanDialog } from "@/components/action-plan/AssociateToPlanDialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Threat, Host } from "@shared/schema";
import { ThreatStats } from "@/types";

// -------------------------
// Evidence label mapping (UIFN-02)
// -------------------------
const EVIDENCE_LABELS: Record<string, string> = {
  port: "Porta",
  protocol: "Protocolo",
  service: "Servico",
  version: "Versao",
  cveId: "CVE",
  severity: "Severidade",
  matcherName: "Correspondencia",
  extractedResults: "Resultados",
  host: "Host",
  ip: "IP",
  hostname: "Hostname",
  os: "Sistema Operacional",
  product: "Produto",
  scriptId: "Script",
  output: "Saida",
  state: "Estado",
  reason: "Razao",
  url: "URL",
  templateId: "Template ID",
  template: "Template",
  matcher: "Matcher",
  vulnerabilityType: "Tipo de Vulnerabilidade",
  banner: "Banner",
  osInfo: "Info SO",
  testId: "Test ID",
  category: "Categoria",
  target: "Dominio",
  command: "Comando",
  remediation: "Remediacao",
  recommendation: "Recomendacao",
};

// AD category labels
const adCategoryLabels: Record<string, string> = {
  users: "Usuarios",
  groups: "Grupos",
  computers: "Computadores",
  policies: "Politicas",
  configuration: "Configuracao",
  kerberos: "Kerberos",
  shares: "Compartilhamentos",
  inactive_accounts: "Contas Inativas",
};

// Helper to parse PowerShell JSON stdout into object array
function tryParseStdoutObjects(stdout: string | undefined): {
  objects: Record<string, any>[] | null;
  keys: string[];
} {
  if (!stdout) return { objects: null, keys: [] };
  try {
    const trimmed = stdout.trim();
    const parsed = JSON.parse(trimmed);
    if (
      Array.isArray(parsed) &&
      parsed.length > 0 &&
      typeof parsed[0] === "object"
    ) {
      const keys = Array.from(
        new Set(parsed.flatMap((obj: any) => Object.keys(obj)))
      );
      return { objects: parsed, keys };
    }
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
    ) {
      return { objects: [parsed], keys: Object.keys(parsed) };
    }
    return { objects: null, keys: [] };
  } catch {
    return { objects: null, keys: [] };
  }
}

function formatCellValue(value: any): string {
  if (value === null || value === undefined) return "\u2014";
  if (typeof value === "boolean") return value ? "Sim" : "Nao";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return Object.entries(value).map(([k, v]) => `${k}: ${v}`).join(", ");
  return String(value);
}

// Render a single evidence value (no JSON.stringify)
function renderEvidenceValue(value: any): React.ReactNode {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "boolean") return value ? "Sim" : "Nao";
  if (Array.isArray(value)) {
    if (value.length === 0) return null;
    return (
      <ul className="list-disc list-inside space-y-0.5">
        {value.map((item, i) => (
          <li key={i} className="text-xs">
            {typeof item === "object"
              ? Object.entries(item)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(", ")
              : String(item)}
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    return (
      <span className="text-xs">
        {Object.entries(value)
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ")}
      </span>
    );
  }
  return <span className="font-mono text-xs">{String(value)}</span>;
}

// Evidence table component (UIFN-02) — no JSON.stringify
function EvidenceTable({ evidence }: { evidence: Record<string, any> }) {
  // Keys to skip from the generic table (handled separately or irrelevant raw)
  const skipKeys = new Set(["stdout", "command"]);
  const entries = Object.entries(evidence).filter(([k, v]) => {
    if (skipKeys.has(k)) return false;
    if (v === null || v === undefined || v === "") return false;
    return true;
  });

  if (entries.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">Sem evidencias estruturadas.</p>
    );
  }

  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
      {entries.map(([k, v]) => {
        const rendered = renderEvidenceValue(v);
        if (rendered === null) return null;
        return (
          <div key={k} className="contents">
            <dt className="text-muted-foreground truncate">
              {EVIDENCE_LABELS[k] ?? k}
            </dt>
            <dd className="break-words">{rendered}</dd>
          </div>
        );
      })}
    </dl>
  );
}

// Remediation preview for parent threat groups (UIFN-04)
function RemediationPreview({ threatId }: { threatId: string }) {
  const { data: rec } = useQuery<any>({
    queryKey: ["/api/threats", threatId, "recommendation"],
    queryFn: () =>
      fetch(`/api/threats/${threatId}/recommendation`).then((r) => {
        if (!r.ok) return null;
        return r.json();
      }),
    enabled: !!threatId,
    staleTime: 60_000,
  });

  if (!rec) {
    return (
      <span className="text-xs text-muted-foreground italic">
        Sem recomendacao
      </span>
    );
  }

  const firstStep =
    Array.isArray(rec.fixSteps) && rec.fixSteps.length > 0
      ? rec.fixSteps[0]
      : null;
  const preview = firstStep
    ? firstStep.length > 80
      ? firstStep.slice(0, 77) + "..."
      : firstStep
    : null;

  return (
    <div className="flex items-center gap-2 mt-1">
      {preview && (
        <span className="text-xs text-muted-foreground truncate max-w-xs">
          {preview}
        </span>
      )}
      {rec.effortTag && (
        <Badge variant="outline" className="text-xs shrink-0">
          {rec.effortTag}
        </Badge>
      )}
    </div>
  );
}

export default function Threats() {
  const [location] = useLocation();
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [hostFilter, setHostFilter] = useState<string>("all");
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [associateDialogOpen, setAssociateDialogOpen] = useState(false);
  const [bulkStatusModal, setBulkStatusModal] = useState<{
    isOpen: boolean;
    newStatus: string;
    justification: string;
    hibernatedUntil: string;
  }>({
    isOpen: false,
    newStatus: "",
    justification: "",
    hibernatedUntil: "",
  });
  const [statusChangeModal, setStatusChangeModal] = useState<{
    threat: Threat | null;
    isOpen: boolean;
    newStatus: string;
    justification: string;
    hibernatedUntil: string;
  }>({
    threat: null,
    isOpen: false,
    newStatus: "",
    justification: "",
    hibernatedUntil: "",
  });

  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { connected } = useWebSocket();

  // Initialize filters from URL parameters
  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const hostId = searchParams.get("hostId");
    const severity = searchParams.get("severity");
    const status = searchParams.get("status");

    if (hostId) setHostFilter(hostId);
    if (severity) setSeverityFilter(severity);
    if (status) setStatusFilter(status);
  }, [location]);

  const { data: threats = [], isLoading } = useQuery<(Threat & { host?: Host })[]>({
    queryKey: ["/api/threats"],
    refetchInterval: 30000,
  });

  const { data: globalStats } = useQuery<ThreatStats>({
    queryKey: ["/api/threats/stats"],
    refetchInterval: 30000,
  });

  // Fetch recommendation for the selected threat detail dialog (UIFN-01, lazy)
  const { data: selectedRecommendation } = useQuery<any>({
    queryKey: ["/api/threats", selectedThreat?.id, "recommendation"],
    queryFn: () =>
      fetch(`/api/threats/${selectedThreat!.id}/recommendation`).then((r) => {
        if (!r.ok) return null;
        return r.json();
      }),
    enabled: !!selectedThreat,
    staleTime: 60_000,
  });

  // Fetch threat status history when a threat is selected
  const { data: statusHistory = [], isLoading: isLoadingHistory } = useQuery<
    any[]
  >({
    queryKey: [`/api/threats/${selectedThreat?.id}/history`],
    enabled: !!selectedThreat,
    refetchInterval: 10000,
  });

  // Calculate filtered stats based on active filters
  const stats = useMemo(() => {
    if (!threats || threats.length === 0) {
      return (
        globalStats || {
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          open: 0,
          investigating: 0,
          mitigated: 0,
          closed: 0,
          hibernated: 0,
          accepted_risk: 0,
        }
      );
    }

    const filtered = threats.filter((t) => {
      if (severityFilter !== "all" && t.severity !== severityFilter)
        return false;
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (hostFilter !== "all" && t.hostId !== hostFilter) return false;
      return true;
    });

    return {
      total: filtered.length,
      critical: filtered.filter((t) => t.severity === "critical").length,
      high: filtered.filter((t) => t.severity === "high").length,
      medium: filtered.filter((t) => t.severity === "medium").length,
      low: filtered.filter((t) => t.severity === "low").length,
      open: filtered.filter((t) => t.status === "open").length,
      investigating: filtered.filter((t) => t.status === "investigating")
        .length,
      mitigated: filtered.filter((t) => t.status === "mitigated").length,
      closed: filtered.filter((t) => t.status === "closed").length,
      hibernated: filtered.filter((t) => t.status === "hibernated").length,
      accepted_risk: filtered.filter((t) => t.status === "accepted_risk")
        .length,
    };
  }, [threats, severityFilter, statusFilter, hostFilter, globalStats]);

  const { data: hosts = [] } = useQuery<Host[]>({
    queryKey: ["/api/hosts"],
    refetchInterval: 60000,
  });

  // Client-side grouping logic (UIFN-03)
  const groupedThreats = useMemo(() => {
    const allThreats = threats as (Threat & { host?: Host })[];
    const parents = allThreats.filter(
      (t) => t.groupingKey !== null && t.parentThreatId === null
    );
    const childMap = new Map<string, (Threat & { host?: Host })[]>();
    allThreats
      .filter((t) => t.parentThreatId !== null)
      .forEach((t) => {
        const pid = t.parentThreatId!;
        if (!childMap.has(pid)) childMap.set(pid, []);
        childMap.get(pid)!.push(t);
      });
    const standalone = allThreats.filter(
      (t) => t.groupingKey === null && t.parentThreatId === null
    );
    return { parents, childMap, standalone };
  }, [threats]);

  // Apply filters to parent/standalone threats
  const matchesThreat = (t: Threat & { host?: Host }) => {
    const matchesSearch =
      t.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (t.description &&
        t.description.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesSeverity =
      severityFilter === "all" || t.severity === severityFilter;
    const matchesStatus =
      statusFilter === "all" || t.status === statusFilter;
    const matchesHost = hostFilter === "all" || t.hostId === hostFilter;
    return matchesSearch && matchesSeverity && matchesStatus && matchesHost;
  };

  // A parent matches if it directly matches OR any of its children match
  const parentMatches = (parent: Threat & { host?: Host }) => {
    if (matchesThreat(parent)) return true;
    const children = groupedThreats.childMap.get(parent.id) || [];
    return children.some(matchesThreat);
  };

  const filteredParents = groupedThreats.parents.filter(parentMatches);
  const filteredStandalone = groupedThreats.standalone.filter(matchesThreat);

  // For bulk select compatibility — flat list of all visible top-level items
  const filteredThreats = [...filteredParents, ...filteredStandalone];

  const updateThreatMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<Threat> }) => {
      return await apiRequest("PATCH", `/api/threats/${id}`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Ameaca atualizada com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats/stats"] });
      if (selectedThreat) {
        queryClient.invalidateQueries({
          queryKey: [`/api/threats/${selectedThreat.id}/history`],
        });
      }
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Nao autorizado",
          description: "Voce foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: "Falha ao atualizar ameaca",
        variant: "destructive",
      });
    },
  });

  const changeStatusMutation = useMutation({
    mutationFn: async ({
      id,
      status,
      justification,
      hibernatedUntil,
    }: {
      id: string;
      status: string;
      justification: string;
      hibernatedUntil?: string;
    }) => {
      const data: any = { status, justification };
      if (hibernatedUntil) {
        data.hibernatedUntil = hibernatedUntil;
      }
      return await apiRequest("PATCH", `/api/threats/${id}/status`, data);
    },
    onSuccess: () => {
      toast({
        title: "Sucesso",
        description: "Status da ameaca atualizado com sucesso",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats/stats"] });
      if (statusChangeModal.threat) {
        queryClient.invalidateQueries({
          queryKey: [`/api/threats/${statusChangeModal.threat.id}/history`],
        });
      }
      setStatusChangeModal({
        threat: null,
        isOpen: false,
        newStatus: "",
        justification: "",
        hibernatedUntil: "",
      });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Nao autorizado",
          description: "Voce foi desconectado. Fazendo login novamente...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: "Falha ao alterar status da ameaca",
        variant: "destructive",
      });
    },
  });

  const handleBulkStatusSubmit = async () => {
    if (
      !bulkStatusModal.justification.trim() ||
      bulkStatusModal.justification.length < 10
    ) {
      toast({
        title: "Erro",
        description: "Justificativa minima de 10 caracteres",
        variant: "destructive",
      });
      return;
    }
    if (
      bulkStatusModal.newStatus === "hibernated" &&
      !bulkStatusModal.hibernatedUntil
    ) {
      toast({
        title: "Erro",
        description: "Data limite e obrigatoria para hibernacao",
        variant: "destructive",
      });
      return;
    }
    const hibernatedUntilISO = bulkStatusModal.hibernatedUntil
      ? new Date(bulkStatusModal.hibernatedUntil).toISOString()
      : undefined;

    try {
      await Promise.all(
        Array.from(selectedIds).map((id) =>
          apiRequest("PATCH", `/api/threats/${id}/status`, {
            status: bulkStatusModal.newStatus,
            justification: bulkStatusModal.justification,
            ...(hibernatedUntilISO ? { hibernatedUntil: hibernatedUntilISO } : {}),
          })
        )
      );
      toast({
        title: "Sucesso",
        description: `${selectedIds.size} ameacas atualizadas`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/threats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/threats/stats"] });
      setSelectedIds(new Set());
      setBulkStatusModal({
        isOpen: false,
        newStatus: "",
        justification: "",
        hibernatedUntil: "",
      });
    } catch {
      toast({
        title: "Erro",
        description: "Falha ao atualizar ameacas em lote",
        variant: "destructive",
      });
    }
  };

  const toggleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(new Set(filteredThreats.map((t) => t.id)));
    } else {
      setSelectedIds(new Set());
    }
  };

  const toggleSelectOne = (id: string, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  };

  const handleExportCSV = () => {
    const headers = ["Severidade", "Titulo", "Host", "IP", "Status", "Fonte", "Detectado em"];
    const rows = filteredThreats.map((t) => [
      getSeverityLabel(t.severity),
      t.title,
      t.host?.name || "",
      t.host?.ips?.[0] || "",
      getStatusLabel(t.status),
      t.source,
      new Date(t.createdAt).toLocaleString("pt-BR"),
    ]);
    const csv = [headers, ...rows]
      .map((row) =>
        row
          .map((cell) => `"${String(cell).replace(/"/g, '""')}"`)
          .join(",")
      )
      .join("\n");
    const blob = new Blob(["\uFEFF" + csv], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threats-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const parsedAdStdout = useMemo(() => {
    return tryParseStdoutObjects(selectedThreat?.evidence?.stdout);
  }, [selectedThreat]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-destructive text-destructive-foreground";
      case "high":
        return "bg-orange-600 text-white";
      case "medium":
        return "bg-accent text-accent-foreground";
      case "low":
        return "bg-chart-4 text-white";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getSeverityLabel = (severity: string) => {
    switch (severity) {
      case "critical":
        return "CRITICA";
      case "high":
        return "ALTA";
      case "medium":
        return "MEDIA";
      case "low":
        return "BAIXA";
      default:
        return severity.toUpperCase();
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open":
        return "bg-destructive/20 text-destructive";
      case "investigating":
        return "bg-accent/20 text-accent";
      case "mitigated":
        return "bg-primary/20 text-primary";
      case "closed":
        return "bg-chart-4/20 text-chart-4";
      case "hibernated":
        return "bg-amber-500/20 text-amber-600";
      case "accepted_risk":
        return "bg-blue-500/20 text-blue-600";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "open":
        return "Aberta";
      case "investigating":
        return "Investigando";
      case "mitigated":
        return "Mitigada";
      case "closed":
        return "Fechada";
      case "hibernated":
        return "Hibernada";
      case "accepted_risk":
        return "Risco Aceito";
      default:
        return status;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "open":
        return AlertTriangle;
      case "investigating":
        return Clock;
      case "mitigated":
      case "closed":
        return CheckCircle;
      case "accepted_risk":
        return Shield;
      default:
        return AlertTriangle;
    }
  };

  const handleStatusChange = (threat: Threat, newStatus: string) => {
    setStatusChangeModal({
      threat,
      isOpen: true,
      newStatus,
      justification: "",
      hibernatedUntil: "",
    });
  };

  const handleStatusSubmit = () => {
    if (
      !statusChangeModal.threat ||
      !statusChangeModal.justification.trim()
    ) {
      toast({
        title: "Erro",
        description: "Justificativa e obrigatoria",
        variant: "destructive",
      });
      return;
    }

    if (
      statusChangeModal.newStatus === "hibernated" &&
      !statusChangeModal.hibernatedUntil
    ) {
      toast({
        title: "Erro",
        description: "Data limite e obrigatoria para hibernacao",
        variant: "destructive",
      });
      return;
    }

    const hibernatedUntilISO = statusChangeModal.hibernatedUntil
      ? new Date(statusChangeModal.hibernatedUntil).toISOString()
      : undefined;

    changeStatusMutation.mutate({
      id: statusChangeModal.threat.id,
      status: statusChangeModal.newStatus,
      justification: statusChangeModal.justification,
      hibernatedUntil: hibernatedUntilISO,
    });
  };

  const formatTimeAgo = (date: string) => {
    const now = new Date();
    const threatDate = new Date(date);
    const diffInMinutes = Math.floor(
      (now.getTime() - threatDate.getTime()) / (1000 * 60)
    );

    if (diffInMinutes < 60) {
      return `${diffInMinutes}m atras`;
    } else if (diffInMinutes < 24 * 60) {
      return `${Math.floor(diffInMinutes / 60)}h atras`;
    } else {
      return `${Math.floor(diffInMinutes / (24 * 60))}d atras`;
    }
  };

  const handleSeverityTileClick = (severity: string) => {
    setSeverityFilter((current) => (current === severity ? "all" : severity));
  };

  const handleStatusTileClick = (status: string) => {
    setStatusFilter((current) => (current === status ? "all" : status));
  };

  const toggleGroup = (id: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Render a single threat row (for standalone threats and children)
  const renderThreatRow = (
    threat: Threat & { host?: Host },
    isChild = false
  ) => {
    const StatusIcon = getStatusIcon(threat.status);
    return (
      <TableRow
        key={threat.id}
        data-testid={`threat-row-${threat.id}`}
        className={`${selectedIds.has(threat.id) ? "bg-primary/5" : ""} ${isChild ? "bg-muted/30" : ""}`}
      >
        <TableCell className={isChild ? "pl-10" : ""}>
          {!isChild && (
            <Checkbox
              checked={selectedIds.has(threat.id)}
              onCheckedChange={(checked) =>
                toggleSelectOne(threat.id, !!checked)
              }
              aria-label={`Selecionar ${threat.title}`}
            />
          )}
        </TableCell>
        <TableCell>
          <Badge className={getSeverityColor(threat.severity)}>
            {getSeverityLabel(threat.severity)}
          </Badge>
        </TableCell>
        <TableCell className="max-w-md">
          <div>
            <button
              className="font-medium text-foreground hover:underline text-left"
              onClick={() => setSelectedThreat(threat)}
            >
              {threat.title}
            </button>
            {threat.description && (
              <p className="text-sm text-muted-foreground truncate">
                {threat.description}
              </p>
            )}
          </div>
        </TableCell>
        <TableCell data-testid={`cell-host-${threat.id}`}>
          {threat.host ? (
            <div className="flex flex-col">
              <span className="font-medium text-foreground">
                {threat.host.name}
              </span>
              <span className="text-xs text-muted-foreground">
                {threat.host.ips?.[0] || "-"}
              </span>
            </div>
          ) : (
            <span className="text-muted-foreground text-sm">N/A</span>
          )}
        </TableCell>
        <TableCell>
          <div className="flex items-center space-x-2">
            <StatusIcon className="h-4 w-4" />
            <Select
              value={threat.status}
              onValueChange={(value) => handleStatusChange(threat, value)}
              disabled={changeStatusMutation.isPending}
            >
              <SelectTrigger className="w-32 h-8">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="open">Aberta</SelectItem>
                <SelectItem value="investigating">Investigando</SelectItem>
                <SelectItem value="mitigated">Mitigada</SelectItem>
                <SelectItem value="hibernated">Hibernada</SelectItem>
                <SelectItem value="accepted_risk">Risco Aceito</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </TableCell>
        <TableCell className="text-muted-foreground">
          {formatTimeAgo(threat.createdAt.toString())}
        </TableCell>
        <TableCell className="text-right">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedThreat(threat)}
            data-testid={`button-view-${threat.id}`}
          >
            <Eye className="h-4 w-4" />
          </Button>
        </TableCell>
      </TableRow>
    );
  };

  // Render parent threat group row with Collapsible (UIFN-03, UIFN-04)
  const renderParentGroup = (parent: Threat & { host?: Host }) => {
    const children = groupedThreats.childMap.get(parent.id) || [];
    const isExpanded = expandedGroups.has(parent.id);
    const StatusIcon = getStatusIcon(parent.status);

    return (
      <Collapsible
        key={parent.id}
        open={isExpanded}
        onOpenChange={() => toggleGroup(parent.id)}
        asChild
      >
        <>
          <TableRow
            data-testid={`threat-row-${parent.id}`}
            className={`${selectedIds.has(parent.id) ? "bg-primary/5" : ""} hover:bg-muted/40`}
          >
            <TableCell>
              <div className="flex items-center gap-2">
                {(() => {
                  const childIds = children.map(c => c.id);
                  const selectedChildCount = childIds.filter(id => selectedIds.has(id)).length;
                  const allChildrenSelected = childIds.length > 0 && selectedChildCount === childIds.length;
                  const someChildrenSelected = selectedChildCount > 0 && !allChildrenSelected;
                  const checkState: boolean | "indeterminate" = allChildrenSelected
                    ? true
                    : someChildrenSelected
                      ? "indeterminate"
                      : false;

                  return (
                    <Checkbox
                      checked={checkState}
                      onCheckedChange={(val) => {
                        setSelectedIds(prev => {
                          const next = new Set(prev);
                          if (val === true) {
                            childIds.forEach(id => next.add(id));
                          } else {
                            childIds.forEach(id => next.delete(id));
                          }
                          return next;
                        });
                      }}
                      aria-label={`Selecionar todas as ameaças do grupo ${parent.title}`}
                    />
                  );
                })()}
                {children.length > 0 && (
                  <CollapsibleTrigger asChild>
                    <button
                      className="p-0.5 hover:bg-muted rounded"
                      aria-label={isExpanded ? "Recolher" : "Expandir"}
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </button>
                  </CollapsibleTrigger>
                )}
              </div>
            </TableCell>
            <TableCell>
              <Badge className={getSeverityColor(parent.severity)}>
                {getSeverityLabel(parent.severity)}
              </Badge>
            </TableCell>
            <TableCell className="max-w-md">
              <div>
                <div className="flex items-center gap-2">
                  <button
                    className="font-medium text-foreground hover:underline text-left"
                    onClick={() => setSelectedThreat(parent)}
                  >
                    {parent.title}
                  </button>
                  {children.length > 0 && (
                    <Badge variant="secondary" className="text-xs shrink-0">
                      {children.length}{" "}
                      {children.length === 1 ? "finding" : "findings"}
                    </Badge>
                  )}
                </div>
                {parent.description && (
                  <p className="text-sm text-muted-foreground truncate">
                    {parent.description}
                  </p>
                )}
                {/* Remediation preview (UIFN-04) */}
                <RemediationPreview threatId={parent.id} />
              </div>
            </TableCell>
            <TableCell data-testid={`cell-host-${parent.id}`}>
              {parent.host ? (
                <div className="flex flex-col">
                  <span className="font-medium text-foreground">
                    {parent.host.name}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {parent.host.ips?.[0] || "-"}
                  </span>
                </div>
              ) : (
                <span className="text-muted-foreground text-sm">N/A</span>
              )}
            </TableCell>
            <TableCell>
              <div className="flex items-center space-x-2">
                <StatusIcon className="h-4 w-4" />
                <Select
                  value={parent.status}
                  onValueChange={(value) => handleStatusChange(parent, value)}
                  disabled={changeStatusMutation.isPending}
                >
                  <SelectTrigger className="w-32 h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Aberta</SelectItem>
                    <SelectItem value="investigating">Investigando</SelectItem>
                    <SelectItem value="mitigated">Mitigada</SelectItem>
                    <SelectItem value="hibernated">Hibernada</SelectItem>
                    <SelectItem value="accepted_risk">Risco Aceito</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </TableCell>
            <TableCell className="text-muted-foreground">
              {formatTimeAgo(parent.createdAt.toString())}
            </TableCell>
            <TableCell className="text-right">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedThreat(parent)}
                data-testid={`button-view-${parent.id}`}
              >
                <Eye className="h-4 w-4" />
              </Button>
            </TableCell>
          </TableRow>

          {/* Child rows inside CollapsibleContent */}
          <CollapsibleContent asChild>
            <>
              {children.filter(matchesThreat).map((child) =>
                renderThreatRow(child, true)
              )}
            </>
          </CollapsibleContent>
        </>
      </Collapsible>
    );
  };

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar />

      <main className="flex-1 overflow-auto">
        <TopBar
          title="Threat Intelligence"
          subtitle="Gerencie e analise ameacas identificadas pelo sistema"
          wsConnected={connected}
          actions={
            <Button
              variant="outline"
              onClick={handleExportCSV}
              disabled={filteredThreats.length === 0}
              data-testid="button-export-threats-csv"
            >
              <Download className="mr-2 h-4 w-4" />
              Exportar CSV
            </Button>
          }
        />

        <div className="p-6 space-y-6">
          {/* Compact Stats Summary */}
          {stats && (
            <div className="space-y-4">
              {/* Severity summary */}
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-muted-foreground" />
                      <span className="text-sm font-medium text-muted-foreground">
                        Total
                      </span>
                      <span className="text-lg font-bold">{stats.total}</span>
                    </div>
                    <div className="h-6 w-px bg-border" />
                    <div className="flex items-center gap-4 flex-1">
                      <button
                        onClick={() => handleSeverityTileClick("critical")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${severityFilter === "critical" ? "ring-1 ring-[var(--severity-critical)]" : ""}`}
                        style={{ backgroundColor: "var(--severity-critical-bg)" }}
                        data-testid="tile-severity-critical"
                      >
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: "var(--severity-critical)" }}
                        />
                        <span
                          className="text-sm font-medium"
                          style={{ color: "var(--severity-critical)" }}
                        >
                          Criticas
                        </span>
                        <span
                          className="text-sm font-bold"
                          style={{ color: "var(--severity-critical)" }}
                        >
                          {stats.critical}
                        </span>
                      </button>
                      <button
                        onClick={() => handleSeverityTileClick("high")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${severityFilter === "high" ? "ring-1 ring-[var(--severity-high)]" : ""}`}
                        style={{ backgroundColor: "var(--severity-high-bg)" }}
                        data-testid="tile-severity-high"
                      >
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: "var(--severity-high)" }}
                        />
                        <span
                          className="text-sm font-medium"
                          style={{ color: "var(--severity-high)" }}
                        >
                          Altas
                        </span>
                        <span
                          className="text-sm font-bold"
                          style={{ color: "var(--severity-high)" }}
                        >
                          {stats.high}
                        </span>
                      </button>
                      <button
                        onClick={() => handleSeverityTileClick("medium")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${severityFilter === "medium" ? "ring-1 ring-[var(--severity-medium)]" : ""}`}
                        style={{ backgroundColor: "var(--severity-medium-bg)" }}
                        data-testid="tile-severity-medium"
                      >
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: "var(--severity-medium)" }}
                        />
                        <span
                          className="text-sm font-medium"
                          style={{ color: "var(--severity-medium)" }}
                        >
                          Medias
                        </span>
                        <span
                          className="text-sm font-bold"
                          style={{ color: "var(--severity-medium)" }}
                        >
                          {stats.medium}
                        </span>
                      </button>
                      <button
                        onClick={() => handleSeverityTileClick("low")}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition-colors ${severityFilter === "low" ? "ring-1 ring-[var(--severity-low)]" : ""}`}
                        style={{ backgroundColor: "var(--severity-low-bg)" }}
                        data-testid="tile-severity-low"
                      >
                        <span
                          className="w-2.5 h-2.5 rounded-full"
                          style={{ backgroundColor: "var(--severity-low)" }}
                        />
                        <span
                          className="text-sm font-medium"
                          style={{ color: "var(--severity-low)" }}
                        >
                          Baixas
                        </span>
                        <span
                          className="text-sm font-bold"
                          style={{ color: "var(--severity-low)" }}
                        >
                          {stats.low}
                        </span>
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Status summary */}
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className="text-sm font-medium text-muted-foreground">
                      Status:
                    </span>
                    {[
                      {
                        key: "open",
                        label: "Abertas",
                        count: stats.open,
                        color: "var(--status-open)",
                      },
                      {
                        key: "investigating",
                        label: "Investigando",
                        count: stats.investigating,
                        color: "var(--status-investigating)",
                      },
                      {
                        key: "mitigated",
                        label: "Mitigadas",
                        count: stats.mitigated,
                        color: "var(--status-mitigated)",
                      },
                      {
                        key: "closed",
                        label: "Fechadas",
                        count: stats.closed,
                        color: "var(--status-closed)",
                      },
                      {
                        key: "hibernated",
                        label: "Hibernadas",
                        count: stats.hibernated,
                        color: "var(--status-hibernated)",
                      },
                      {
                        key: "accepted_risk",
                        label: "Risco Aceito",
                        count: stats.accepted_risk,
                        color: "var(--status-accepted)",
                      },
                    ].map((item) => (
                      <button
                        key={item.key}
                        onClick={() => handleStatusTileClick(item.key)}
                        className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-sm transition-colors hover:bg-muted ${statusFilter === item.key ? "bg-muted ring-1 ring-border" : ""}`}
                        data-testid={`tile-status-${item.key.replace("_", "-")}`}
                      >
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-muted-foreground">
                          {item.label}
                        </span>
                        <span
                          className="font-semibold"
                          style={{ color: item.color }}
                        >
                          {item.count}
                        </span>
                      </button>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Search and Filters */}
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder="Buscar ameacas por titulo ou descricao..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                    data-testid="input-search-threats"
                  />
                </div>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger
                    className="w-48"
                    data-testid="select-severity-filter"
                  >
                    <SelectValue placeholder="Filtrar por severidade" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todas as Severidades</SelectItem>
                    <SelectItem value="critical">Critica</SelectItem>
                    <SelectItem value="high">Alta</SelectItem>
                    <SelectItem value="medium">Media</SelectItem>
                    <SelectItem value="low">Baixa</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger
                    className="w-48"
                    data-testid="select-status-filter"
                  >
                    <SelectValue placeholder="Filtrar por status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Status</SelectItem>
                    <SelectItem value="open">Aberta</SelectItem>
                    <SelectItem value="investigating">Investigando</SelectItem>
                    <SelectItem value="mitigated">Mitigada</SelectItem>
                    <SelectItem value="hibernated">Hibernada</SelectItem>
                    <SelectItem value="accepted_risk">Risco Aceito</SelectItem>
                    <SelectItem value="closed">Fechada</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={hostFilter} onValueChange={setHostFilter}>
                  <SelectTrigger
                    className="w-48"
                    data-testid="select-host-filter"
                  >
                    <SelectValue placeholder="Filtrar por host" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos os Hosts</SelectItem>
                    {hosts.map((host) => (
                      <SelectItem key={host.id} value={host.id}>
                        {host.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Badge variant="secondary" data-testid="threats-count">
                  {filteredParents.length + filteredStandalone.length} grupos/ameacas
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Threats Table */}
          <Card>
            <CardHeader>
              <CardTitle>Ameacas Identificadas</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-3">
                  {[...Array(5)].map((_, i) => (
                    <div key={i} className="flex items-center space-x-4 p-3">
                      <Skeleton className="h-4 w-4 rounded" />
                      <Skeleton className="h-6 w-16 rounded-full" />
                      <div className="flex-1 space-y-1">
                        <Skeleton className="h-4 w-3/4" />
                        <Skeleton className="h-3 w-1/2" />
                      </div>
                      <Skeleton className="h-4 w-24" />
                      <Skeleton className="h-8 w-32 rounded-md" />
                      <Skeleton className="h-4 w-16" />
                    </div>
                  ))}
                </div>
              ) : filteredParents.length === 0 &&
                filteredStandalone.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium text-foreground mb-2">
                    {searchTerm ||
                    severityFilter !== "all" ||
                    statusFilter !== "all"
                      ? "Nenhuma ameaca encontrada"
                      : "Nenhuma ameaca identificada"}
                  </h3>
                  <p className="text-muted-foreground">
                    {searchTerm ||
                    severityFilter !== "all" ||
                    statusFilter !== "all"
                      ? "Tente ajustar os filtros de busca"
                      : "Execute jornadas para identificar ameacas"}
                  </p>
                </div>
              ) : (
                <>
                  {/* Bulk Action Bar */}
                  {selectedIds.size > 0 && (
                    <div className="flex items-center justify-between p-3 mb-4 bg-primary/10 border border-primary/20 rounded-lg">
                      <span className="text-sm font-medium">
                        {selectedIds.size} ameaca(s) selecionada(s)
                      </span>
                      <div className="flex items-center space-x-2">
                        <Select
                          onValueChange={(value) =>
                            setBulkStatusModal({
                              isOpen: true,
                              newStatus: value,
                              justification: "",
                              hibernatedUntil: "",
                            })
                          }
                        >
                          <SelectTrigger className="w-44 h-8">
                            <SelectValue placeholder="Alterar status..." />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="open">Aberta</SelectItem>
                            <SelectItem value="investigating">
                              Investigando
                            </SelectItem>
                            <SelectItem value="mitigated">Mitigada</SelectItem>
                            <SelectItem value="hibernated">Hibernada</SelectItem>
                            <SelectItem value="accepted_risk">
                              Risco Aceito
                            </SelectItem>
                          </SelectContent>
                        </Select>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setAssociateDialogOpen(true)}
                          disabled={selectedIds.size === 0}
                        >
                          <ClipboardList className="h-4 w-4 mr-1" /> Associar a Plano de Ação
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedIds(new Set())}
                        >
                          Limpar selecao
                        </Button>
                      </div>
                    </div>
                  )}
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-16">
                            <Checkbox
                              checked={
                                filteredThreats.length > 0 &&
                                selectedIds.size === filteredThreats.length
                              }
                              onCheckedChange={(checked) =>
                                toggleSelectAll(!!checked)
                              }
                              aria-label="Selecionar todas"
                            />
                          </TableHead>
                          <TableHead>Severidade</TableHead>
                          <TableHead>Titulo / Remediacao</TableHead>
                          <TableHead>Host</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Detectado em</TableHead>
                          <TableHead className="text-right">Acoes</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {/* Parent groups with children */}
                        {filteredParents.map((parent) =>
                          renderParentGroup(parent)
                        )}
                        {/* Standalone threats */}
                        {filteredStandalone.map((threat) =>
                          renderThreatRow(threat, false)
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </main>

      {/* Threat Details Dialog (UIFN-01) */}
      <Dialog
        open={!!selectedThreat}
        onOpenChange={() => setSelectedThreat(null)}
      >
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Detalhes da Ameaca</DialogTitle>
          </DialogHeader>
          {selectedThreat && (
            <div className="space-y-6">
              {/* Header with badges */}
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-xl font-semibold text-foreground mb-2">
                    {selectedThreat.title}
                  </h3>
                  <div className="flex items-center flex-wrap gap-2 mb-2">
                    <Badge className={getSeverityColor(selectedThreat.severity)}>
                      {getSeverityLabel(selectedThreat.severity)}
                    </Badge>
                    <Badge className={getStatusColor(selectedThreat.status)}>
                      {getStatusLabel(selectedThreat.status)}
                    </Badge>
                    {selectedRecommendation?.effortTag && (
                      <Badge variant="outline">
                        Esforco: {selectedRecommendation.effortTag}
                      </Badge>
                    )}
                    {selectedRecommendation?.roleRequired && (
                      <Badge variant="outline">
                        Papel: {selectedRecommendation.roleRequired}
                      </Badge>
                    )}
                  </div>
                </div>
              </div>

              {/* Section 1: Problema (UIFN-01) */}
              <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-lg">
                <h4 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 text-destructive" />
                  Problema
                </h4>
                <p className="text-sm text-foreground/80 leading-relaxed">
                  {selectedRecommendation?.whatIsWrong ||
                    selectedThreat.description ||
                    "Sem descricao disponivel."}
                </p>
              </div>

              {/* Section 2: Impacto (UIFN-01) */}
              <div className="p-4 bg-orange-500/5 border border-orange-500/20 rounded-lg">
                <h4 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-orange-600" />
                  Impacto
                </h4>
                <p className="text-sm text-foreground/80 leading-relaxed">
                  {selectedRecommendation?.businessImpact ||
                    "Impacto nao avaliado."}
                </p>
              </div>

              {/* Section 3: Correcao (UIFN-01) */}
              <div className="p-4 bg-primary/5 border border-primary/20 rounded-lg">
                <h4 className="font-semibold text-foreground mb-3 flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-primary" />
                  Correcao
                </h4>
                {selectedRecommendation?.fixSteps &&
                Array.isArray(selectedRecommendation.fixSteps) &&
                selectedRecommendation.fixSteps.length > 0 ? (
                  <div className="space-y-3">
                    <ol className="space-y-2">
                      {selectedRecommendation.fixSteps.map(
                        (step: string, i: number) => (
                          <li key={i} className="flex gap-3 text-sm">
                            <span className="flex-shrink-0 w-5 h-5 bg-primary/20 text-primary rounded-full flex items-center justify-center text-xs font-bold">
                              {i + 1}
                            </span>
                            <span className="text-foreground/80 leading-relaxed">
                              {step}
                            </span>
                          </li>
                        )
                      )}
                    </ol>
                    {selectedRecommendation.verificationStep && (
                      <div className="mt-3 pt-3 border-t border-primary/10">
                        <div className="flex items-center gap-2 mb-1">
                          <ListChecks className="h-4 w-4 text-primary" />
                          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                            Verificacao
                          </span>
                        </div>
                        <p className="text-sm text-foreground/70">
                          {selectedRecommendation.verificationStep}
                        </p>
                      </div>
                    )}
                    {selectedRecommendation.references &&
                      Array.isArray(selectedRecommendation.references) &&
                      selectedRecommendation.references.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-primary/10">
                          <p className="text-xs font-medium text-muted-foreground mb-1">
                            Referencias:
                          </p>
                          <ul className="space-y-0.5">
                            {selectedRecommendation.references.map(
                              (ref: string, i: number) => (
                                <li key={i} className="text-xs text-primary hover:underline">
                                  <a href={ref} target="_blank" rel="noopener noreferrer">
                                    {ref}
                                  </a>
                                </li>
                              )
                            )}
                          </ul>
                        </div>
                      )}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Sem passos de correcao disponíveis.
                  </p>
                )}
              </div>

              {/* Metadata */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-foreground mb-2">Informacoes</h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Fonte:</span>
                      <span>{selectedThreat.source}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Detectado em:
                      </span>
                      <span>
                        {new Date(selectedThreat.createdAt).toLocaleString(
                          "pt-BR"
                        )}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Atualizado em:
                      </span>
                      <span>
                        {new Date(selectedThreat.updatedAt).toLocaleString(
                          "pt-BR"
                        )}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Evidence — labeled key-value (UIFN-02) */}
              {selectedThreat.evidence &&
                Object.keys(selectedThreat.evidence).length > 0 && (
                  <div>
                    <h4 className="font-medium text-foreground mb-4">
                      Evidencias
                    </h4>

                    {/* AD Security Test Info */}
                    {selectedThreat.evidence.testId && (
                      <div className="p-4 bg-indigo-500/10 border border-indigo-500/30 rounded-md mb-4">
                        <h5 className="font-medium text-sm text-foreground mb-2 flex items-center gap-2">
                          <Shield className="h-4 w-4 text-indigo-500" />
                          Teste AD Security
                        </h5>
                        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                          <dt className="text-muted-foreground">Test ID:</dt>
                          <dd className="font-mono text-xs">
                            {selectedThreat.evidence.testId}
                          </dd>
                          {selectedThreat.evidence.category && (
                            <>
                              <dt className="text-muted-foreground">
                                Categoria:
                              </dt>
                              <dd>
                                {adCategoryLabels[
                                  selectedThreat.evidence.category
                                ] || selectedThreat.evidence.category}
                              </dd>
                            </>
                          )}
                          {selectedThreat.evidence.target && (
                            <>
                              <dt className="text-muted-foreground">
                                Dominio:
                              </dt>
                              <dd className="font-mono text-xs">
                                {selectedThreat.evidence.target}
                              </dd>
                            </>
                          )}
                        </dl>
                      </div>
                    )}

                    {/* AD Parsed Objects Table */}
                    {selectedThreat.evidence.testId &&
                      parsedAdStdout.objects &&
                      parsedAdStdout.objects.length > 0 && (
                        <div className="p-4 bg-muted/50 border rounded-md mb-4">
                          <h5 className="font-medium text-sm text-foreground mb-2">
                            Objetos Afetados ({parsedAdStdout.objects.length})
                          </h5>
                          <div className="max-h-64 overflow-auto border rounded-md bg-background">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  {parsedAdStdout.keys.map((key) => (
                                    <TableHead
                                      key={key}
                                      className="text-xs whitespace-nowrap"
                                    >
                                      {key}
                                    </TableHead>
                                  ))}
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {parsedAdStdout.objects.map((obj, idx) => (
                                  <TableRow key={idx}>
                                    {parsedAdStdout.keys.map((key) => (
                                      <TableCell
                                        key={key}
                                        className="text-xs font-mono whitespace-nowrap"
                                      >
                                        {formatCellValue(obj[key])}
                                      </TableCell>
                                    ))}
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </div>
                        </div>
                      )}

                    {/* Generic evidence key-value table (UIFN-02) */}
                    <div className="p-4 bg-muted/30 border rounded-md">
                      <EvidenceTable evidence={selectedThreat.evidence} />
                    </div>

                    {/* AD Command (collapsible) */}
                    {selectedThreat.evidence.testId &&
                      selectedThreat.evidence.command && (
                        <details className="mt-4 p-4 bg-muted/50 border rounded-md">
                          <summary className="text-sm font-medium text-foreground cursor-pointer hover:text-foreground/80">
                            Comando PowerShell Executado
                          </summary>
                          <pre className="mt-2 p-3 bg-background rounded-md text-xs overflow-x-auto font-mono">
                            {selectedThreat.evidence.command}
                          </pre>
                        </details>
                      )}
                  </div>
                )}

              {/* Status History Section */}
              <div>
                <h4 className="font-medium text-foreground mb-4">
                  Historico de Status
                </h4>
                {isLoadingHistory ? (
                  <div className="text-center py-4">
                    <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
                    <p className="text-sm text-muted-foreground">
                      Carregando historico...
                    </p>
                  </div>
                ) : statusHistory.length > 0 ? (
                  <div className="space-y-3 max-h-64 overflow-y-auto">
                    {statusHistory.map((entry: any, index: number) => (
                      <div
                        key={index}
                        className="p-3 bg-muted/50 border rounded-md"
                        data-testid={`status-history-${index}`}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            {entry.fromStatus && (
                              <Badge variant="outline" className="text-xs">
                                {getStatusLabel(entry.fromStatus)}
                              </Badge>
                            )}
                            <span className="text-muted-foreground text-xs">
                              →
                            </span>
                            <Badge
                              className={
                                getStatusColor(entry.toStatus) + " text-xs"
                              }
                            >
                              {getStatusLabel(entry.toStatus)}
                            </Badge>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(
                              entry.changedAt || entry.createdAt
                            ).toLocaleString("pt-BR")}
                          </span>
                        </div>
                        {entry.justification && (
                          <p className="text-sm text-muted-foreground mb-2">
                            {entry.justification}
                          </p>
                        )}
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">
                            Por: {entry.changedBy?.firstName}{" "}
                            {entry.changedBy?.lastName} (
                            {entry.changedBy?.email})
                          </span>
                          {entry.hibernatedUntil && (
                            <span className="text-muted-foreground">
                              Hibernado ate:{" "}
                              {new Date(
                                entry.hibernatedUntil
                              ).toLocaleString("pt-BR")}
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-4">
                    <p className="text-sm text-muted-foreground">
                      Sem historico de mudancas de status ainda
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Status Change Modal */}
      <Dialog
        open={statusChangeModal.isOpen}
        onOpenChange={(open) =>
          !open &&
          setStatusChangeModal({
            threat: null,
            isOpen: false,
            newStatus: "",
            justification: "",
            hibernatedUntil: "",
          })
        }
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Alterar Status da Ameaca</DialogTitle>
          </DialogHeader>
          {statusChangeModal.threat && (
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Ameaca:</p>
                <p className="font-medium">{statusChangeModal.threat.title}</p>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">
                  Status atual:
                </p>
                <Badge
                  className={getStatusColor(statusChangeModal.threat.status)}
                >
                  {getStatusLabel(statusChangeModal.threat.status)}
                </Badge>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">
                  Novo status:
                </p>
                <Badge className={getStatusColor(statusChangeModal.newStatus)}>
                  {getStatusLabel(statusChangeModal.newStatus)}
                </Badge>
              </div>

              <div>
                <label className="text-sm font-medium text-foreground">
                  Justificativa *
                </label>
                <textarea
                  className={`mt-1 w-full min-h-[80px] px-3 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                    statusChangeModal.justification.length > 0 &&
                    statusChangeModal.justification.length < 10
                      ? "border-red-500 focus:ring-red-500 bg-red-50 dark:bg-red-950/20 text-gray-900 dark:text-gray-100"
                      : "border-input focus:ring-ring bg-background text-foreground"
                  }`}
                  placeholder="Descreva o motivo da mudanca de status..."
                  value={statusChangeModal.justification}
                  onChange={(e) =>
                    setStatusChangeModal((prev) => ({
                      ...prev,
                      justification: e.target.value,
                    }))
                  }
                  data-testid="textarea-justification"
                />
                <div className="flex items-center justify-between mt-1">
                  {statusChangeModal.justification.length < 10 ? (
                    <p className="text-xs text-red-600 dark:text-red-400">
                      Minimo de 10 caracteres necessario
                    </p>
                  ) : (
                    <p className="text-xs text-green-600 dark:text-green-400">
                      Justificativa valida
                    </p>
                  )}
                  <span
                    className={`text-xs ${
                      statusChangeModal.justification.length < 10
                        ? "text-red-600 dark:text-red-400 font-medium"
                        : "text-muted-foreground"
                    }`}
                  >
                    {statusChangeModal.justification.length}/10
                  </span>
                </div>
              </div>

              {statusChangeModal.newStatus === "hibernated" && (
                <div>
                  <label className="text-sm font-medium text-foreground">
                    Data limite para reativacao *
                  </label>
                  <Input
                    type="datetime-local"
                    className="mt-1"
                    value={statusChangeModal.hibernatedUntil}
                    onChange={(e) =>
                      setStatusChangeModal((prev) => ({
                        ...prev,
                        hibernatedUntil: e.target.value,
                      }))
                    }
                    min={new Date().toISOString().slice(0, 16)}
                    data-testid="input-hibernated-until"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    A ameaca sera reativada automaticamente nesta data
                  </p>
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-4">
                <Button
                  variant="outline"
                  onClick={() =>
                    setStatusChangeModal({
                      threat: null,
                      isOpen: false,
                      newStatus: "",
                      justification: "",
                      hibernatedUntil: "",
                    })
                  }
                  disabled={changeStatusMutation.isPending}
                  data-testid="button-cancel-status-change"
                >
                  Cancelar
                </Button>
                <Button
                  onClick={handleStatusSubmit}
                  disabled={
                    changeStatusMutation.isPending ||
                    statusChangeModal.justification.length < 10 ||
                    (statusChangeModal.newStatus === "hibernated" &&
                      !statusChangeModal.hibernatedUntil)
                  }
                  data-testid="button-confirm-status-change"
                >
                  {changeStatusMutation.isPending
                    ? "Alterando..."
                    : "Confirmar"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Bulk Status Change Modal */}
      <Dialog
        open={bulkStatusModal.isOpen}
        onOpenChange={(open) =>
          !open &&
          setBulkStatusModal({
            isOpen: false,
            newStatus: "",
            justification: "",
            hibernatedUntil: "",
          })
        }
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Alterar Status em Lote</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Alterar <strong>{selectedIds.size}</strong> ameaca(s) para{" "}
              <Badge className={getStatusColor(bulkStatusModal.newStatus)}>
                {getStatusLabel(bulkStatusModal.newStatus)}
              </Badge>
            </p>

            <div>
              <label className="text-sm font-medium text-foreground">
                Justificativa *
              </label>
              <textarea
                className={`mt-1 w-full min-h-[80px] px-3 py-2 text-sm border rounded-md focus:outline-none focus:ring-2 ${
                  bulkStatusModal.justification.length > 0 &&
                  bulkStatusModal.justification.length < 10
                    ? "border-red-500 focus:ring-red-500 bg-red-50 dark:bg-red-950/20 text-gray-900 dark:text-gray-100"
                    : "border-input focus:ring-ring bg-background text-foreground"
                }`}
                placeholder="Descreva o motivo da mudanca de status em lote..."
                value={bulkStatusModal.justification}
                onChange={(e) =>
                  setBulkStatusModal((prev) => ({
                    ...prev,
                    justification: e.target.value,
                  }))
                }
                data-testid="textarea-bulk-justification"
              />
              <div className="flex items-center justify-between mt-1">
                {bulkStatusModal.justification.length < 10 ? (
                  <p className="text-xs text-red-600 dark:text-red-400">
                    Minimo de 10 caracteres
                  </p>
                ) : (
                  <p className="text-xs text-green-600 dark:text-green-400">
                    Justificativa valida
                  </p>
                )}
                <span
                  className={`text-xs ${bulkStatusModal.justification.length < 10 ? "text-red-600 dark:text-red-400 font-medium" : "text-muted-foreground"}`}
                >
                  {bulkStatusModal.justification.length}/10
                </span>
              </div>
            </div>

            {bulkStatusModal.newStatus === "hibernated" && (
              <div>
                <label className="text-sm font-medium text-foreground">
                  Data limite para reativacao *
                </label>
                <Input
                  type="datetime-local"
                  className="mt-1"
                  value={bulkStatusModal.hibernatedUntil}
                  onChange={(e) =>
                    setBulkStatusModal((prev) => ({
                      ...prev,
                      hibernatedUntil: e.target.value,
                    }))
                  }
                  min={new Date().toISOString().slice(0, 16)}
                  data-testid="input-bulk-hibernated-until"
                />
              </div>
            )}

            <div className="flex justify-end space-x-2 pt-4">
              <Button
                variant="outline"
                onClick={() =>
                  setBulkStatusModal({
                    isOpen: false,
                    newStatus: "",
                    justification: "",
                    hibernatedUntil: "",
                  })
                }
                data-testid="button-cancel-bulk-status"
              >
                Cancelar
              </Button>
              <Button
                onClick={handleBulkStatusSubmit}
                disabled={
                  bulkStatusModal.justification.length < 10 ||
                  (bulkStatusModal.newStatus === "hibernated" &&
                    !bulkStatusModal.hibernatedUntil)
                }
                data-testid="button-confirm-bulk-status"
              >
                Alterar {selectedIds.size} Ameacas
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <AssociateToPlanDialog
        open={associateDialogOpen}
        onOpenChange={setAssociateDialogOpen}
        threatIds={Array.from(selectedIds)}
        onSuccess={() => {
          setSelectedIds(new Set());
        }}
      />
    </div>
  );
}
