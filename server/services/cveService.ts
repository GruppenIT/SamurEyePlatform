interface CVEResult {
  cveId: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number;
  publishedDate: string;
  remediation: string;
  affectedVersions?: string[]; // Versões afetadas extraídas da descrição
  confidence?: 'high' | 'medium' | 'low'; // Confiança de que este CVE se aplica
}

interface NVDMetric {
  cvssData?: {
    baseScore: number;
    baseSeverity: string;
  };
}

interface NVDCVEItem {
  cve: {
    id: string;
    descriptions: Array<{
      lang: string;
      value: string;
    }>;
    published: string;
    metrics?: {
      cvssMetricV31?: NVDMetric[];
      cvssMetricV30?: NVDMetric[];
      cvssMetricV2?: NVDMetric[];
    };
  };
}

class CVEService {
  private readonly NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly REQUEST_DELAY = 6000; // 6 segundos entre requisições (rate limit do NVD)
  private lastRequestTime = 0;
  private cache = new Map<string, CVEResult[]>();

  /**
   * Busca CVEs para um serviço e versão específicos
   * Retorna apenas CVEs que realmente se aplicam à versão fornecida
   */
  async searchCVEs(service: string, version?: string, osInfo?: string): Promise<CVEResult[]> {
    // Normalizar nome do serviço para busca
    const searchTerm = this.normalizeServiceName(service, version);
    
    // Verificar cache
    const cacheKey = `${service}:${version || 'latest'}`;
    if (this.cache.has(cacheKey)) {
      console.log(`📦 CVE cache hit para ${cacheKey}`);
      return this.filterCVEsByVersion(this.cache.get(cacheKey)!, version, osInfo);
    }

    console.log(`🔍 Buscando CVEs para: ${searchTerm} (versão: ${version || 'N/A'}, OS: ${osInfo || 'N/A'})`);

    try {
      // Rate limiting - aguardar entre requisições
      await this.waitForRateLimit();

      // Consultar API do NVD
      const url = `${this.NVD_API_BASE}?keywordSearch=${encodeURIComponent(searchTerm)}&resultsPerPage=20`;
      
      const response = await fetch(url, {
        headers: {
          'Accept': 'application/json',
        },
      });

      if (!response.ok) {
        console.error(`❌ Erro na API NVD: ${response.status} ${response.statusText}`);
        return [];
      }

      const data = await response.json();
      const cves: CVEResult[] = [];

      if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
        for (const vuln of data.vulnerabilities) {
          const cveItem = vuln.cve as NVDCVEItem['cve'];
          const cveResult = this.parseCVE(cveItem);
          if (cveResult) {
            cves.push(cveResult);
          }
        }
      }

      console.log(`✅ Encontrados ${cves.length} CVEs brutos para ${searchTerm}`);

      // Armazenar em cache
      this.cache.set(cacheKey, cves);

      // Filtrar por versão antes de retornar
      const filteredCves = this.filterCVEsByVersion(cves, version, osInfo);
      console.log(`✅ Após filtragem por versão: ${filteredCves.length} CVEs aplicáveis`);

      return filteredCves;
    } catch (error) {
      console.error(`❌ Erro ao buscar CVEs para ${searchTerm}:`, error);
      return [];
    }
  }

  /**
   * Filtra CVEs baseado na versão detectada e OS info
   * Remove CVEs que claramente não se aplicam à versão/OS detectado
   */
  private filterCVEsByVersion(cves: CVEResult[], detectedVersion?: string, osInfo?: string): CVEResult[] {
    if (!detectedVersion && !osInfo) {
      // Sem informação de versão/OS, retornar tudo mas marcar confiança baixa
      return cves.map(cve => ({ ...cve, confidence: 'low' as const }));
    }

    const filtered: CVEResult[] = [];

    for (const cve of cves) {
      const match = this.matchesCVEVersion(cve, detectedVersion, osInfo);
      
      if (match.applies) {
        filtered.push({
          ...cve,
          confidence: match.confidence,
        });
      }
    }

    return filtered;
  }

  /**
   * Verifica se um CVE se aplica à versão/OS detectado
   * Retorna { applies: boolean, confidence: 'high'|'medium'|'low' }
   */
  private matchesCVEVersion(
    cve: CVEResult, 
    detectedVersion?: string, 
    osInfo?: string
  ): { applies: boolean; confidence: 'high' | 'medium' | 'low' } {
    const description = cve.description.toLowerCase();
    
    // Extrair versões afetadas da descrição
    const versionRanges = this.extractAffectedVersions(cve.description);
    
    // Se temos OS info, validar contra ela
    if (osInfo) {
      const osLower = osInfo.toLowerCase();
      
      // Exemplo: CVE para Windows 2008-2012 não deve aplicar a Windows 2016
      if (description.includes('windows') || description.includes('microsoft')) {
        // Extrair versões do Windows da descrição do CVE
        const cveWindowsVersions = this.extractWindowsVersions(description);
        const detectedWindowsVersion = this.extractWindowsVersions(osLower);
        
        if (cveWindowsVersions.length > 0 && detectedWindowsVersion.length > 0) {
          // Verificar se há overlap entre versões do CVE e versão detectada
          const hasMatch = cveWindowsVersions.some(cveVer => 
            detectedWindowsVersion.includes(cveVer)
          );
          
          if (!hasMatch) {
            console.log(`❌ CVE ${cve.cveId} não se aplica: ${cveWindowsVersions.join(', ')} vs ${detectedWindowsVersion.join(', ')}`);
            return { applies: false, confidence: 'high' };
          }
          
          console.log(`✅ CVE ${cve.cveId} se aplica: match de versão Windows`);
          return { applies: true, confidence: 'high' };
        }
      }
    }

    // Se temos versão detectada, validar contra ela
    if (detectedVersion && versionRanges.length > 0) {
      const parsedDetected = this.parseVersion(detectedVersion);
      
      for (const range of versionRanges) {
        if (this.isVersionInRange(parsedDetected, range)) {
          console.log(`✅ CVE ${cve.cveId} se aplica: versão ${detectedVersion} está em ${range}`);
          return { applies: true, confidence: 'high' };
        }
      }
      
      // Versão fornecida mas não está no range
      console.log(`❌ CVE ${cve.cveId} não se aplica: versão ${detectedVersion} fora do range`);
      return { applies: false, confidence: 'high' };
    }

    // Sem informação suficiente para validar - incluir mas com confiança média
    return { applies: true, confidence: 'medium' };
  }

  /**
   * Extrai versões do Windows de uma string
   * Ex: "Windows Server 2008 R2, 2012" -> ['2008', '2012']
   */
  private extractWindowsVersions(text: string): string[] {
    const versions: string[] = [];
    
    // Padrões de versão do Windows
    const patterns = [
      /windows\s+(?:server\s+)?(\d{4})/gi,
      /(?:server|vista|xp|7|8|10|11)[\s\.]?r?(\d)?/gi,
    ];
    
    for (const pattern of patterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        if (match[1]) {
          versions.push(match[1]);
        }
      }
    }
    
    return [...new Set(versions)]; // Remove duplicatas
  }

  /**
   * Extrai versões afetadas da descrição do CVE
   * Ex: "versions 1.0 through 2.5" -> ["1.0-2.5"]
   */
  private extractAffectedVersions(description: string): string[] {
    const ranges: string[] = [];
    
    // Padrão: "version(s) X through Y" ou "version(s) X to Y"
    const rangePattern = /version[s]?\s+([\d.]+)\s+(?:through|to)\s+([\d.]+)/gi;
    const matches = description.matchAll(rangePattern);
    
    for (const match of matches) {
      ranges.push(`${match[1]}-${match[2]}`);
    }
    
    // Padrão: "version X"
    const singlePattern = /version\s+([\d.]+)/gi;
    const singleMatches = description.matchAll(singlePattern);
    
    for (const match of singleMatches) {
      ranges.push(match[1]);
    }
    
    return ranges;
  }

  /**
   * Parse de versão para array de números
   * Ex: "2.5.1" -> [2, 5, 1]
   */
  private parseVersion(version: string): number[] {
    const cleaned = version.replace(/[^\d.]/g, '');
    return cleaned.split('.').map(v => parseInt(v) || 0);
  }

  /**
   * Verifica se uma versão está dentro de um range
   */
  private isVersionInRange(version: number[], range: string): boolean {
    if (range.includes('-')) {
      const [start, end] = range.split('-');
      const startVer = this.parseVersion(start);
      const endVer = this.parseVersion(end);
      
      return this.compareVersions(version, startVer) >= 0 && 
             this.compareVersions(version, endVer) <= 0;
    } else {
      const exactVer = this.parseVersion(range);
      return this.compareVersions(version, exactVer) === 0;
    }
  }

  /**
   * Compara duas versões
   * Retorna: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
   */
  private compareVersions(v1: number[], v2: number[]): number {
    const maxLen = Math.max(v1.length, v2.length);
    
    for (let i = 0; i < maxLen; i++) {
      const num1 = v1[i] || 0;
      const num2 = v2[i] || 0;
      
      if (num1 < num2) return -1;
      if (num1 > num2) return 1;
    }
    
    return 0;
  }

  /**
   * Normaliza o nome do serviço para busca efetiva
   */
  private normalizeServiceName(service: string, version?: string): string {
    // Mapeamento de serviços conhecidos para produtos NVD
    const serviceMap: Record<string, string> = {
      'ms-sql-s': 'Microsoft SQL Server',
      'mssql': 'Microsoft SQL Server',
      'mysql': 'MySQL',
      'postgresql': 'PostgreSQL',
      'postgres': 'PostgreSQL',
      'http': 'Apache httpd',
      'https': 'Apache httpd',
      'nginx': 'nginx',
      'apache': 'Apache',
      'ssh': 'OpenSSH',
      'openssh': 'OpenSSH',
      'microsoft-ds': 'Windows SMB',
      'netbios-ssn': 'Windows NetBIOS',
      'msrpc': 'Windows RPC',
      'ms-wbt-server': 'Microsoft Terminal Services',
      'rdp': 'Microsoft Remote Desktop',
    };

    let searchTerm = serviceMap[service.toLowerCase()] || service;
    
    // Adicionar versão se disponível
    if (version) {
      // Extrair versão numérica (ex: "13.00.1742" -> "13.00")
      const versionMatch = version.match(/(\d+\.?\d*)/);
      if (versionMatch) {
        searchTerm += ` ${versionMatch[1]}`;
      }
    }

    return searchTerm;
  }

  /**
   * Parse de um item CVE do NVD
   */
  private parseCVE(cveItem: NVDCVEItem['cve']): CVEResult | null {
    try {
      // Obter descrição em inglês
      const englishDesc = cveItem.descriptions.find(d => d.lang === 'en');
      if (!englishDesc) {
        return null;
      }

      // Obter CVSS score e severity
      const metrics = cveItem.metrics;
      let cvssScore = 0;
      let baseSeverity = 'UNKNOWN';

      // Priorizar CVSS v3.1, depois v3.0, depois v2
      if (metrics?.cvssMetricV31?.[0]?.cvssData) {
        cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
        baseSeverity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
      } else if (metrics?.cvssMetricV30?.[0]?.cvssData) {
        cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
        baseSeverity = metrics.cvssMetricV30[0].cvssData.baseSeverity;
      } else if (metrics?.cvssMetricV2?.[0]?.cvssData) {
        cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
        baseSeverity = metrics.cvssMetricV2[0].cvssData.baseSeverity || this.scoresToSeverity(cvssScore);
      }

      // Converter severity do NVD para nosso padrão
      const severity = this.mapSeverity(baseSeverity, cvssScore);

      // Traduzir descrição e gerar recomendação em PT-BR
      const translatedDesc = this.translateDescription(englishDesc.value, cveItem.id);
      const remediation = this.generateRemediation(cveItem.id, severity);

      return {
        cveId: cveItem.id,
        description: translatedDesc,
        severity,
        cvssScore,
        publishedDate: cveItem.published,
        remediation,
      };
    } catch (error) {
      console.error(`Erro ao processar CVE:`, error);
      return null;
    }
  }

  /**
   * Converte score numérico para severity
   */
  private scoresToSeverity(score: number): string {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Mapeia severity do NVD para nosso padrão
   */
  private mapSeverity(nvdSeverity: string, cvssScore: number): 'low' | 'medium' | 'high' | 'critical' {
    const severity = nvdSeverity.toUpperCase();
    
    if (severity === 'CRITICAL' || cvssScore >= 9.0) return 'critical';
    if (severity === 'HIGH' || cvssScore >= 7.0) return 'high';
    if (severity === 'MEDIUM' || cvssScore >= 4.0) return 'medium';
    return 'low';
  }

  /**
   * Traduz descrição do CVE para PT-BR
   */
  private translateDescription(englishDesc: string, cveId: string): string {
    // Para manter simplicidade, criar descrição estruturada em PT-BR
    // baseada em padrões comuns de CVE
    
    const commonPatterns: Array<[RegExp, string]> = [
      [/buffer overflow/i, 'Vulnerabilidade de estouro de buffer'],
      [/sql injection/i, 'Vulnerabilidade de injeção SQL'],
      [/cross-site scripting|xss/i, 'Vulnerabilidade de Cross-Site Scripting (XSS)'],
      [/remote code execution|rce/i, 'Vulnerabilidade de execução remota de código'],
      [/denial of service|dos/i, 'Vulnerabilidade de negação de serviço (DoS)'],
      [/privilege escalation/i, 'Vulnerabilidade de escalação de privilégios'],
      [/authentication bypass/i, 'Vulnerabilidade de contorno de autenticação'],
      [/directory traversal/i, 'Vulnerabilidade de travessia de diretório'],
      [/information disclosure/i, 'Vulnerabilidade de divulgação de informações'],
      [/memory corruption/i, 'Vulnerabilidade de corrupção de memória'],
    ];

    for (const [pattern, translation] of commonPatterns) {
      if (pattern.test(englishDesc)) {
        return `${translation} identificada no sistema (${cveId}). ${this.extractKeyInfo(englishDesc)}`;
      }
    }

    // Fallback: descrição genérica em PT-BR
    return `Vulnerabilidade de segurança identificada (${cveId}). ${this.extractKeyInfo(englishDesc)}`;
  }

  /**
   * Extrai informações-chave da descrição
   */
  private extractKeyInfo(desc: string): string {
    // Extrair versão afetada se presente
    const versionMatch = desc.match(/version[s]?\s+([\d.]+(?:\s+(?:through|to|and)\s+[\d.]+)?)/i);
    if (versionMatch) {
      return `Afeta versão(ões): ${versionMatch[1]}.`;
    }

    // Extrair produto se presente
    const productMatch = desc.match(/in\s+([A-Z][A-Za-z\s]+(?:\d+)?)/);
    if (productMatch) {
      return `Encontrada em: ${productMatch[1]}.`;
    }

    return 'Requer análise detalhada e aplicação de correções de segurança.';
  }

  /**
   * Gera recomendação de correção em PT-BR
   */
  private generateRemediation(cveId: string, severity: string): string {
    const baseRemediation = `Para corrigir a vulnerabilidade ${cveId}:`;
    
    const recommendations = [
      `1. **Atualizar Sistema**: Aplicar as atualizações de segurança mais recentes do fornecedor`,
      `2. **Verificar Patches**: Consultar o boletim de segurança oficial para patches específicos`,
      `3. **Medidas Compensatórias**: Implementar controles de segurança adicionais enquanto o patch não é aplicado`,
      `4. **Monitoramento**: Aumentar monitoramento de logs e atividades suspeitas relacionadas`,
      `5. **Referência**: Consultar https://nvd.nist.gov/vuln/detail/${cveId} para detalhes técnicos`,
    ];

    if (severity === 'critical' || severity === 'high') {
      recommendations.unshift(`⚠️ **PRIORIDADE ${severity === 'critical' ? 'CRÍTICA' : 'ALTA'}**: Esta vulnerabilidade deve ser corrigida imediatamente.`);
    }

    return `${baseRemediation}\n\n${recommendations.join('\n')}`;
  }

  /**
   * Aguarda rate limit do NVD (6 segundos entre requisições)
   */
  private async waitForRateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.REQUEST_DELAY) {
      const waitTime = this.REQUEST_DELAY - timeSinceLastRequest;
      console.log(`⏱️ Aguardando ${waitTime}ms para rate limit do NVD...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Limpa cache (útil para testes)
   */
  clearCache(): void {
    this.cache.clear();
    console.log('🗑️ Cache de CVE limpo');
  }
}

export const cveService = new CVEService();
