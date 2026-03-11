// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Executor de Jornadas - orquestra scanners e processa resultados
// Trecho representativo (server/services/journeyExecutor.ts)

import { storage } from '../storage';
import { threatEngine } from './threatEngine';
import { encryptionService } from './encryption';
import { networkScanner } from './scanners/networkScanner';
import { vulnScanner } from './scanners/vulnScanner';
import { ADScanner } from './scanners/adScanner';
import { EDRAVScanner } from './scanners/edrAvScanner';
import { jobQueue } from './jobQueue';
import { hostService } from './hostService';
import { processTracker } from './processTracker';
import { cveService } from './cveService';
import { hostEnricher } from './hostEnricher';
import { WMICollector } from './collectors/wmiCollector';
import { SSHCollector } from './collectors/sshCollector';
import { type Journey, type Job } from '@shared/schema';

const adScanner = new ADScanner();

// Registra coletores de enrichment
hostEnricher.registerCollector(new WMICollector());
hostEnricher.registerCollector(new SSHCollector());

export interface JourneyProgress {
  status: Job['status'];
  progress: number;
  currentTask: string;
}

type ProgressCallback = (progress: JourneyProgress) => void;

class JourneyExecutorService {
  /**
   * Resolve IDs de ativos com base no modo de selecao
   * Se targetSelectionMode = 'by_tag', expande TAGs em assetIds
   * Se targetSelectionMode = 'individual', usa assetIds dos params
   */
  private async resolveAssetIds(journey: Journey): Promise<string[]> {
    if (journey.targetSelectionMode === 'by_tag' && journey.selectedTags?.length) {
      const assets = await storage.getAssetsByTags(journey.selectedTags);
      return assets.map(a => a.id);
    }
    return journey.params.assetIds || [];
  }

  /**
   * Executa uma jornada de acordo com seu tipo:
   * - attack_surface: nmap (scan de portas) + nuclei (vulnerabilidades web) + CVE detection
   * - ad_security: analise LDAP de Active Directory (politicas, usuarios, grupos)
   * - edr_av: teste EICAR em hosts do AD via SMB/WinRM
   * - web_application: scan de aplicacoes web descobertas
   */
  async executeJourney(
    journey: Journey,
    jobId: string,
    onProgress: ProgressCallback
  ): Promise<void> {
    onProgress({ status: 'running', progress: 10, currentTask: 'Preparando execucao' });

    const assetIds = await this.resolveAssetIds(journey);
    if (assetIds.length === 0) {
      throw new Error('Nenhum ativo selecionado para esta jornada');
    }

    switch (journey.type) {
      case 'attack_surface':
        await this.executeAttackSurface(journey, jobId, assetIds, onProgress);
        break;
      case 'ad_security':
        await this.executeADSecurity(journey, jobId, assetIds, onProgress);
        break;
      case 'edr_av':
        await this.executeEDRAV(journey, jobId, assetIds, onProgress);
        break;
      case 'web_application':
        await this.executeWebApplication(journey, jobId, assetIds, onProgress);
        break;
    }
  }

  // Attack Surface: nmap scan + nuclei + host enrichment + CVE detection
  private async executeAttackSurface(
    journey: Journey, jobId: string, assetIds: string[], onProgress: ProgressCallback
  ): Promise<void> {
    // 1. Resolve ativos para IPs/FQDNs
    // 2. Executa nmap com perfil configurado
    // 3. Processa resultados e cria/atualiza hosts
    // 4. Executa nuclei para vulnerabilidades web
    // 5. Enrichment via WMI/SSH (se credenciais configuradas)
    // 6. Deteccao de CVEs (se habilitado)
    // 7. Alimenta Threat Engine com achados
    // [implementacao completa omitida - ver codigo-fonte]
  }

  // AD Security: analise LDAP de politicas, usuarios e grupos
  private async executeADSecurity(
    journey: Journey, jobId: string, assetIds: string[], onProgress: ProgressCallback
  ): Promise<void> {
    // 1. Conecta ao DC via LDAP (credencial AD)
    // 2. Executa bateria de testes de seguranca
    // 3. Registra resultados (pass/fail) em ad_security_test_results
    // 4. Gera ameacas para falhas detectadas
    // [implementacao completa omitida - ver codigo-fonte]
  }

  // EDR/AV: teste EICAR em hosts via SMB/WinRM
  private async executeEDRAV(
    journey: Journey, jobId: string, assetIds: string[], onProgress: ProgressCallback
  ): Promise<void> {
    // 1. Seleciona amostra de hosts do AD
    // 2. Deposita arquivo EICAR via SMB
    // 3. Aguarda timeout configurado
    // 4. Verifica se arquivo foi removido pelo EDR/AV
    // 5. Gera ameaca se EICAR persistir
    // [implementacao completa omitida - ver codigo-fonte]
  }

  // Web Application: scan de aplicacoes web descobertas
  private async executeWebApplication(
    journey: Journey, jobId: string, assetIds: string[], onProgress: ProgressCallback
  ): Promise<void> {
    // 1. Resolve URLs de web applications
    // 2. Executa nuclei com templates web
    // 3. Gera ameacas para vulnerabilidades encontradas
    // [implementacao completa omitida - ver codigo-fonte]
  }
}
