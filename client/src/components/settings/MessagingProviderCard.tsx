import type { KeyboardEvent, ReactNode } from "react";
import { CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

export interface MessagingProviderCardProps {
  id: "google" | "microsoft" | "smtp";
  name: string;
  subtitle: string;
  logo: ReactNode;
  selected: boolean;
  configured: boolean;
  onSelect: () => void;
  tabIndex?: number;
  onKeyDown?: (event: KeyboardEvent<HTMLButtonElement>) => void;
}

export function MessagingProviderCard({
  id,
  name,
  subtitle,
  logo,
  selected,
  configured,
  onSelect,
  tabIndex,
  onKeyDown,
}: MessagingProviderCardProps) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      tabIndex={tabIndex}
      onClick={onSelect}
      onKeyDown={onKeyDown}
      data-testid={`card-messaging-provider-${id}`}
      className={cn(
        "relative flex min-h-[120px] w-full flex-col items-start gap-2 rounded-lg border bg-card p-4 text-left transition-colors",
        "hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        selected
          ? "border-primary bg-primary/5 ring-2 ring-primary"
          : "border-border",
      )}
    >
      {configured && (
        <span
          data-testid={`badge-messaging-provider-configured-${id}`}
          className="absolute right-3 top-3 inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-600 dark:text-green-400"
        >
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
          Configurado
        </span>
      )}
      <div className="flex h-8 w-8 items-center justify-center">{logo}</div>
      <div>
        <div className="text-base font-semibold leading-tight">{name}</div>
        <div className="mt-0.5 text-sm text-muted-foreground">{subtitle}</div>
      </div>
    </button>
  );
}
