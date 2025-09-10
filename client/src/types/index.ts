export interface DashboardMetrics {
  activeAssets: number;
  criticalThreats: number;
  jobsExecuted: number;
  coverage: number;
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
  type: 'attack_surface' | 'ad_hygiene' | 'edr_av';
  description?: string;
  params: Record<string, any>;
}

export interface ScheduleFormData {
  journeyId: string;
  name: string;
  kind: 'on_demand' | 'once' | 'recurring';
  cronExpression?: string;
  onceAt?: Date;
  enabled: boolean;
}
