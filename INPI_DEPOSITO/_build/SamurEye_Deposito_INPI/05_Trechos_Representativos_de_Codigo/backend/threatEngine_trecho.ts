// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Motor de ameacas (Threat Engine) - correlacao e classificacao automatica
// Trecho representativo das regras de deteccao

import { storage } from '../storage';
import { hostService } from './hostService';
import { type InsertThreat, type Threat } from '@shared/schema';
import { notificationService } from './notificationService';

export interface ThreatRule {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matcher: (finding: any) => boolean;
  createThreat: (finding: any, assetId?: string, jobId?: string) => InsertThreat;
}

// Classificacao de servicos por categoria para severidade dinamica
type ServiceCategory = 'admin' | 'database' | 'sharing' | 'web' | 'email' | 'infrastructure' | 'other';

const SERVICE_CATEGORIES: Record<ServiceCategory, {
  label: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  ports: Set<string>;
  serviceNames: Set<string>;
}> = {
  admin: {
    label: 'Administracao',
    severity: 'high',
    ports: new Set(['22', '23', '3389', '5900', '5901', '5902', '5985', '5986']),
    serviceNames: new Set(['ssh', 'telnet', 'ms-wbt-server', 'rdp', 'vnc', 'winrm']),
  },
  database: {
    label: 'Banco de Dados',
    severity: 'high',
    ports: new Set(['1433', '1521', '3306', '5432', '6379', '9042', '9200', '27017']),
    serviceNames: new Set(['ms-sql-s', 'mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch']),
  },
  sharing: {
    label: 'Compartilhamento',
    severity: 'high',
    ports: new Set(['21', '69', '139', '445', '873', '2049']),
    serviceNames: new Set(['ftp', 'tftp', 'microsoft-ds', 'netbios-ssn', 'smb', 'nfs']),
  },
  web: {
    label: 'Web',
    severity: 'medium',
    ports: new Set(['80', '443', '8080', '8443', '8000', '3000']),
    serviceNames: new Set(['http', 'https', 'http-proxy', 'nginx', 'apache']),
  },
  email: {
    label: 'E-mail',
    severity: 'medium',
    ports: new Set(['25', '110', '143', '465', '587', '993', '995']),
    serviceNames: new Set(['smtp', 'pop3', 'imap', 'imaps', 'smtps']),
  },
  infrastructure: {
    label: 'Infraestrutura',
    severity: 'medium',
    ports: new Set(['53', '88', '123', '161', '389', '636']),
    serviceNames: new Set(['domain', 'dns', 'kerberos', 'ntp', 'snmp', 'ldap']),
  },
  other: {
    label: 'Outro',
    severity: 'low',
    ports: new Set(),
    serviceNames: new Set(),
  },
};

class ThreatEngineService {
  private rules: ThreatRule[] = [];

  constructor() {
    this.initializeRules();
  }

  // Classifica porta/servico em categoria para atribuicao de severidade
  private classifyServiceCategory(port: string, service?: string) {
    const cleanPort = String(port).replace(/\/(tcp|udp)$/i, '');
    const svcLower = (service || '').toLowerCase();
    for (const [cat, cfg] of Object.entries(SERVICE_CATEGORIES)) {
      if (cat === 'other') continue;
      if (cfg.ports.has(cleanPort)) return { category: cat, label: cfg.label, severity: cfg.severity };
    }
    for (const [cat, cfg] of Object.entries(SERVICE_CATEGORIES)) {
      if (cat === 'other') continue;
      if (svcLower && cfg.serviceNames.has(svcLower)) return { category: cat, label: cfg.label, severity: cfg.severity };
    }
    return { category: 'other', label: 'Outro', severity: 'low' as const };
  }

  // Inicializa regras de deteccao de ameacas
  // Regras incluem: portas expostas, vulnerabilidades nuclei, achados AD, falhas EDR/AV
  private initializeRules(): void {
    // [regras de deteccao omitidas por brevidade - ver codigo-fonte completo]
  }

  // Processa achados e gera ameacas correlacionadas
  async processFindings(findings: any[], assetId?: string, jobId?: string): Promise<Threat[]> {
    // [implementacao omitida - ver codigo-fonte completo]
    return [];
  }

  // Monitor de hibernacao para reativacao automatica de ameacas
  async startHibernationMonitor(): Promise<void> {
    // [implementacao omitida - ver codigo-fonte completo]
  }
}
