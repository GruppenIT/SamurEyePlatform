export interface DashboardMetrics {
  activeAssets: number;
  criticalThreats: number;
  jobsExecuted: number;
  successRate: number;
}

export interface JobUpdate {
  jobId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'timeout';
  progress?: number;
  currentTask?: string;
  error?: string;
}

export interface ThreatStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  investigating: number;
  mitigated: number;
  closed: number;
  hibernated: number;
  accepted_risk: number;
}

export interface AssetFormData {
  type: 'host' | 'range';
  value: string;
  tags: string[];
}

export interface CredentialFormData {
  name: string;
  type: 'ssh' | 'wmi' | 'omi' | 'ad';
  hostOverride?: string;
  port?: number;
  username: string;
  secret: string;
}

export interface JourneyFormData {
  name: string;
  type: 'attack_surface' | 'ad_security' | 'edr_av';
  description?: string;
  params: Record<string, any>;
}

export interface ScheduleFormData {
  journeyId: string;
  name: string;
  kind: 'on_demand' | 'once' | 'recurring';
  // Campos legados (mantidos para compatibilidade)
  cronExpression?: string;
  // Campos para execução única
  onceAt?: Date;
  // Campos para execução recorrente
  recurrenceType?: 'daily' | 'weekly' | 'monthly';
  hour?: number;
  minute?: number;
  dayOfWeek?: number; // 0=Sunday, 6=Saturday
  dayOfMonth?: number; // 1-31
  // Campos de intervalo customizado (Repetir a cada X)
  repeatInterval?: number; // Número de unidades
  repeatUnit?: 'hours' | 'days'; // Unidade de tempo
  enabled: boolean;
}
