import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import JourneyForm from "./journey-form";
import {
  Search,
  Users,
  Globe,
  Code2,
  Shield,
  ChevronRight,
  ArrowLeft,
  AlertCircle,
} from "lucide-react";
import { Journey } from "@shared/schema";
import { JourneyFormData } from "@/types";

// Worm icon isn't in lucide-react, use Shield as fallback for edr_av
const Worm = Shield;

interface JourneyType {
  type: string;
  name: string;
  description: string;
  Icon: React.ComponentType<{ className?: string }>;
  colorClass: string;
  bgClass: string;
  constraint?: string;
}

const JOURNEY_TYPES: JourneyType[] = [
  {
    type: "attack_surface",
    name: "Attack Surface",
    description:
      "Varredura de portas, serviços e CVEs em hosts e ranges de rede. Identifica exposições e vulnerabilidades conhecidas.",
    Icon: Search,
    colorClass: "text-primary",
    bgClass: "bg-primary/10",
  },
  {
    type: "ad_security",
    name: "AD Security",
    description:
      "Auditoria completa do Active Directory — políticas de senha, GPOs, contas privilegiadas e configurações críticas.",
    Icon: Users,
    colorClass: "text-violet-500",
    bgClass: "bg-violet-500/10",
    constraint: "1 por domínio",
  },
  {
    type: "edr_av",
    name: "Teste EDR/AV",
    description:
      "Valida a eficácia das soluções de proteção de endpoints simulando ameaças reais na rede.",
    Icon: Worm,
    colorClass: "text-orange-500",
    bgClass: "bg-orange-500/10",
  },
  {
    type: "web_application",
    name: "Web Application",
    description:
      "Descoberta e análise de vulnerabilidades em aplicações web — injeções, exposições e configurações incorretas.",
    Icon: Globe,
    colorClass: "text-blue-500",
    bgClass: "bg-blue-500/10",
  },
  {
    type: "api_security",
    name: "API Security",
    description:
      "Descoberta de endpoints e testes OWASP API Top 10 em APIs REST e GraphQL, com suporte a spec OpenAPI.",
    Icon: Code2,
    colorClass: "text-emerald-500",
    bgClass: "bg-emerald-500/10",
  },
];

interface JourneyCreatorModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (data: JourneyFormData) => void;
  isLoading: boolean;
  journeys: Journey[];
}

export function JourneyCreatorModal({
  open,
  onOpenChange,
  onSubmit,
  isLoading,
  journeys,
}: JourneyCreatorModalProps) {
  const [step, setStep] = useState<"picker" | "form">("picker");
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const { toast } = useToast();

  // Reset when dialog closes
  useEffect(() => {
    if (!open) {
      const t = setTimeout(() => {
        setStep("picker");
        setSelectedType(null);
      }, 250);
      return () => clearTimeout(t);
    }
  }, [open]);

  const handleTypeSelect = (type: string) => {
    setSelectedType(type);
    setStep("form");
  };

  const handleBack = () => {
    setStep("picker");
    setSelectedType(null);
  };

  const handleSubmit = (data: JourneyFormData) => {
    // AD Security: validate domain uniqueness
    if (data.type === "ad_security") {
      const domain = (data.params?.domain as string | undefined)?.toLowerCase()?.trim();
      if (domain) {
        const conflict = journeys.find(
          (j) =>
            j.type === "ad_security" &&
            (j.params as any)?.domain?.toLowerCase()?.trim() === domain
        );
        if (conflict) {
          toast({
            title: "Domínio já configurado",
            description: `Já existe uma jornada AD Security para o domínio "${domain}". Edite a jornada existente ou escolha outro domínio.`,
            variant: "destructive",
          });
          return;
        }
      }
    }
    onSubmit(data);
  };

  const selectedTypeDef = JOURNEY_TYPES.find((t) => t.type === selectedType);

  // Existing AD domains (for showing a warning on the card)
  const existingAdDomains = journeys
    .filter((j) => j.type === "ad_security" && (j.params as any)?.domain)
    .map((j) => (j.params as any).domain as string);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className={
          step === "picker"
            ? "max-w-2xl"
            : "max-w-4xl max-h-[90vh] overflow-y-auto"
        }
      >
        {/* ── STEP 1: Type picker ── */}
        {step === "picker" && (
          <>
            <DialogHeader className="pb-2">
              <DialogTitle className="text-xl">Nova Jornada</DialogTitle>
              <p className="text-sm text-muted-foreground mt-1">
                Escolha o tipo de jornada que deseja configurar
              </p>
            </DialogHeader>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 py-2">
              {JOURNEY_TYPES.map(({ type, name, description, Icon, colorClass, bgClass, constraint }) => {
                const isAdType = type === "ad_security";
                const hasExistingAd = isAdType && existingAdDomains.length > 0;

                return (
                  <button
                    key={type}
                    className="group relative flex items-start gap-4 rounded-xl border-2 border-border bg-card hover:border-primary/40 hover:bg-muted/40 transition-all duration-200 text-left p-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                    onClick={() => handleTypeSelect(type)}
                    aria-label={`Selecionar jornada ${name}`}
                  >
                    {/* Icon */}
                    <div className={`shrink-0 mt-0.5 p-2.5 rounded-lg ${bgClass}`}>
                      <Icon className={`h-5 w-5 ${colorClass}`} />
                    </div>

                    {/* Text */}
                    <div className="flex-1 min-w-0 pr-6">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-foreground text-sm">{name}</span>
                        {constraint && (
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0 shrink-0">
                            {constraint}
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        {description}
                      </p>

                      {/* Warning: existing AD domains */}
                      {hasExistingAd && (
                        <div className="mt-2 flex items-start gap-1.5 rounded-md bg-yellow-500/10 border border-yellow-500/20 px-2 py-1.5">
                          <AlertCircle className="h-3 w-3 text-yellow-500 mt-0.5 shrink-0" />
                          <p className="text-[11px] text-yellow-600 dark:text-yellow-400 leading-tight">
                            Domínios existentes:{" "}
                            <span className="font-mono font-medium">
                              {existingAdDomains.join(", ")}
                            </span>
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Arrow indicator */}
                    <ChevronRight className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground/40 group-hover:text-primary group-hover:translate-x-0.5 transition-all duration-150" />
                  </button>
                );
              })}
            </div>
          </>
        )}

        {/* ── STEP 2: Type-specific form ── */}
        {step === "form" && selectedType && (
          <>
            <DialogHeader className="pb-2">
              <div className="flex items-center gap-3">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleBack}
                  className="h-8 w-8 p-0 -ml-1 shrink-0"
                  aria-label="Voltar para seleção de tipo"
                >
                  <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                  <div className="flex items-center gap-2">
                    {selectedTypeDef && (
                      <selectedTypeDef.Icon
                        className={`h-4 w-4 ${selectedTypeDef.colorClass}`}
                      />
                    )}
                    <DialogTitle className="text-lg">
                      Nova jornada — {selectedTypeDef?.name}
                    </DialogTitle>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Passo 2 de 2 — Configure os parâmetros da jornada
                  </p>
                </div>
              </div>
            </DialogHeader>

            <JourneyForm
              key={selectedType}
              typeOverride={selectedType}
              onSubmit={handleSubmit}
              onCancel={handleBack}
              isLoading={isLoading}
            />
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
