import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { AlertTriangle, XCircle } from "lucide-react";

interface SubscriptionStatus {
  configured: boolean;
  status: string;
  readOnly: boolean;
  expiresAt: string | null;
  graceDeadline: string | null;
  consecutiveFailures: number;
}

/**
 * Global banner displayed at the very top of the page when subscription
 * is expired, in grace period, or console is unreachable.
 * Only visible to authenticated users.
 */
export default function SubscriptionBanner() {
  const { isAuthenticated } = useAuth();

  const { data: subscription } = useQuery<SubscriptionStatus>({
    queryKey: ['/api/subscription/status'],
    enabled: isAuthenticated,
    refetchInterval: 60_000,
    // Don't show loading states - just hide until loaded
    staleTime: 30_000,
  });

  // Don't show banner in these cases
  if (!isAuthenticated) return null;
  if (!subscription) return null;
  if (!subscription.configured) return null;
  if (subscription.status === 'active') return null;

  const isExpired = subscription.status === 'expired';
  const isGrace = subscription.status === 'grace_period';
  const isUnreachable = subscription.status === 'unreachable';

  if (!isExpired && !isGrace && !isUnreachable) return null;

  const bgColor = isExpired
    ? 'bg-destructive text-destructive-foreground'
    : isGrace
      ? 'bg-yellow-600 text-white'
      : 'bg-orange-600 text-white';

  const Icon = isExpired ? XCircle : AlertTriangle;

  const message = isExpired
    ? 'Subscrição expirada. O SamurEye está em modo somente-leitura. Contate o administrador para renovar.'
    : isGrace
      ? `Console central inacessível (${subscription.consecutiveFailures} tentativas). O acesso será limitado se a conexão não for restabelecida.`
      : 'Console central inacessível há mais de 72 horas. O SamurEye está em modo somente-leitura.';

  return (
    <div className={`${bgColor} px-4 py-2 text-center text-sm font-medium flex items-center justify-center gap-2 z-50`}>
      <Icon className="h-4 w-4 flex-shrink-0" />
      <span>{message}</span>
    </div>
  );
}
