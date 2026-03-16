import type { Threat, Host } from '@shared/schema';

export type EffortTag = 'minutes' | 'hours' | 'days' | 'weeks';
export type RoleRequired = 'sysadmin' | 'developer' | 'security' | 'vendor';
export type HostFamily = 'linux' | 'windows_server' | 'windows_desktop' | 'fortios' | 'network_os' | 'other';

export interface RecommendationContext {
  threat: Threat;
  host?: Host;
  hostFamily: HostFamily;
  evidence: Record<string, any>;
  childEvidences?: Array<Record<string, any>>;
}

export interface GeneratedRecommendation {
  title: string;
  whatIsWrong: string;
  businessImpact: string;
  fixSteps: string[];
  verificationStep: string;
  references: string[];
  effortTag: EffortTag;
  roleRequired: RoleRequired;
  hostSpecificData: Record<string, any>;
}

export type TemplateGenerator = (ctx: RecommendationContext) => GeneratedRecommendation;
