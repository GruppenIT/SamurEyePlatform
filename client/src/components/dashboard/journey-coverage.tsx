import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import { Globe, Shield, ShieldCheck, Code, Lock, CheckCircle, XCircle, Circle } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface CoverageItem {
  journeyType: string;
  lastRunAt: string | null;
  lastStatus: "completed" | "failed" | "timeout" | null;
  openThreatCount: number;
}

const journeyLabels: Record<string, string> = {
  attack_surface: "Superfície de Ataque",
  ad_security: "Segurança AD",
  edr_av: "EDR/Antivírus",
  web_application: "Aplicação Web",
  api_security: "API Security",
};

const journeyIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  attack_surface: Globe,
  ad_security: Shield,
  edr_av: ShieldCheck,
  web_application: Code,
  api_security: Lock,
};

function StatusIcon({ status }: { status: CoverageItem["lastStatus"] }) {
  if (status === "completed") {
    return <CheckCircle className="h-4 w-4 text-green-500" />;
  }
  if (status === "failed" || status === "timeout") {
    return <XCircle className="h-4 w-4 text-red-500" />;
  }
  return <Circle className="h-4 w-4 text-muted-foreground" />;
}

export default function JourneyCoverage() {
  const { data: coverage = [], isLoading } = useQuery<CoverageItem[]>({
    queryKey: ["/api/posture/coverage"],
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="p-4 text-center text-muted-foreground text-sm">
        Carregando cobertura...
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-4 p-4">
      {coverage.map((item) => {
        const Icon = journeyIcons[item.journeyType] ?? Globe;
        const label = journeyLabels[item.journeyType] ?? item.journeyType;

        return (
          <div
            key={item.journeyType}
            className="flex flex-col gap-2 rounded-lg border border-border bg-muted/30 p-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Icon className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">{label}</span>
              </div>
              <StatusIcon status={item.lastStatus} />
            </div>
            <div className="text-xs text-muted-foreground">
              {item.lastRunAt
                ? format(new Date(item.lastRunAt), "dd/MM/yyyy HH:mm")
                : "Nunca executada"}
            </div>
            <div>
              <Badge variant="secondary" className="text-xs">
                {item.openThreatCount} abertas
              </Badge>
            </div>
          </div>
        );
      })}
    </div>
  );
}
