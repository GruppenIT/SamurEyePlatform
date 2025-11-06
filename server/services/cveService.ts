interface CVEResult {
  cveId: string;
  description: string; // Descrição traduzida para PT-BR (exibição)
  descriptionEnglish: string; // Descrição original em inglês (parsing)
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number;
  publishedDate: string;
  remediation: string;
  affectedVersions?: string[]; // Versões afetadas extraídas da descrição
  cpeMatches?: CPEMatch[]; // CPE configurations do NVD (fonte confiável)
  confidence?: 'high' | 'medium' | 'low'; // Confiança de que este CVE se aplica
}

interface CPEMatch {
  criteria: string; // CPE URI (ex: cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*)
  matchCriteriaId?: string;
  versionStartIncluding?: string;
  versionEndIncluding?: string;
  versionStartExcluding?: string;
  versionEndExcluding?: string;
  vulnerable?: boolean;
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
    configurations?: Array<{
      nodes: Array<{
        operator?: string;
        cpeMatch?: CPEMatch[];
      }>;
    }>;
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
   * Usa CPE como fonte primária (mais confiável), depois descrição
   * Retorna { applies: boolean, confidence: 'high'|'medium'|'low' }
   */
  private matchesCVEVersion(
    cve: CVEResult, 
    detectedVersion?: string, 
    osInfo?: string
  ): { applies: boolean; confidence: 'high' | 'medium' | 'low' } {
    const descriptionEn = cve.descriptionEnglish.toLowerCase();
    
    // ESTRATÉGIA 1: Usar CPE matches (fonte mais confiável) - SEMPRE tentar
    if (cve.cpeMatches && cve.cpeMatches.length > 0) {
      const cpeResult = this.matchAgainstCPE(cve.cpeMatches, osInfo, detectedVersion);
      if (cpeResult !== null) {
        if (cpeResult.applies) {
          console.log(`✅ CVE ${cve.cveId} se aplica via CPE: ${cpeResult.reason}`);
        } else {
          console.log(`❌ CVE ${cve.cveId} NÃO se aplica via CPE: ${cpeResult.reason}`);
        }
        return { applies: cpeResult.applies, confidence: 'high' };
      }
    }
    
    // ESTRATÉGIA 2: Windows version matching (específico e confiável)
    if (osInfo && (descriptionEn.includes('windows') || descriptionEn.includes('microsoft'))) {
      const osLower = osInfo.toLowerCase();
      const cveWindowsVersions = this.extractWindowsVersions(descriptionEn);
      const detectedWindowsVersion = this.extractWindowsVersions(osLower);
      
      if (cveWindowsVersions.length > 0 && detectedWindowsVersion.length > 0) {
        const hasMatch = cveWindowsVersions.some(cveVer => 
          detectedWindowsVersion.includes(cveVer)
        );
        
        if (!hasMatch) {
          console.log(`❌ CVE ${cve.cveId} NÃO se aplica: Windows ${cveWindowsVersions.join(', ')} vs detectado ${detectedWindowsVersion.join(', ')}`);
          return { applies: false, confidence: 'high' };
        }
        
        console.log(`✅ CVE ${cve.cveId} se aplica: Windows ${cveWindowsVersions.join(', ')} match`);
        return { applies: true, confidence: 'high' };
      }
    }

    // ESTRATÉGIA 3: Version range matching via descrição INGLESA (menos confiável)
    if (detectedVersion) {
      const versionRanges = this.extractAffectedVersions(cve.descriptionEnglish);
      
      if (versionRanges.length > 0) {
        const parsedDetected = this.parseVersion(detectedVersion);
        
        for (const range of versionRanges) {
          if (this.isVersionInRange(parsedDetected, range)) {
            console.log(`✅ CVE ${cve.cveId} se aplica: versão ${detectedVersion} em range ${range}`);
            return { applies: true, confidence: 'high' };
          }
        }
        
        // Versão detectada mas está FORA do range especificado
        console.log(`❌ CVE ${cve.cveId} NÃO se aplica: versão ${detectedVersion} fora de todos os ranges`);
        return { applies: false, confidence: 'high' };
      }
    }

    // ESTRATÉGIA 4: Sem informação suficiente - REJEITAR por segurança
    // Se não conseguimos validar, não podemos afirmar que o CVE se aplica
    console.log(`❌ CVE ${cve.cveId} NÃO se aplica: informação insuficiente para validação (sem CPE, sem versão Windows, sem version range)`);
    return { applies: false, confidence: 'low' };
  }

  /**
   * Valida contra CPE matches (fonte mais confiável do NVD)
   * Itera TODOS os CPEs antes de decidir, priorizando matches positivos
   * Retorna null se CPE não se aplica ao contexto detectado
   */
  private matchAgainstCPE(
    cpeMatches: CPEMatch[], 
    osInfo: string | undefined, 
    serviceVersion?: string
  ): { applies: boolean; reason: string } | null {
    const osLower = osInfo?.toLowerCase() || '';
    
    let foundRelevantCPE = false; // Flag: encontramos CPE relevante ao contexto
    const mismatches: string[] = []; // Acumular mismatches para logging
    
    for (const cpe of cpeMatches) {
      // Pular CPEs explicitamente marcadas como não-vulneráveis
      if (cpe.vulnerable === false) {
        console.log(`⏭️  Pulando CPE não-vulnerável: ${cpe.criteria}`);
        continue;
      }
      
      // Parse CPE: cpe:2.3:part:vendor:product:version:...
      const parts = cpe.criteria.split(':');
      if (parts.length < 5) continue;
      
      const [, , part, vendor, product, version] = parts;
      
      // Verificar se é OS CPE (part = 'o') ou aplicação (part = 'a')
      const isOS = part === 'o';
      
      // Match de OS (requer osInfo)
      if (isOS && osInfo) {
        foundRelevantCPE = true;
        
        if (osLower.includes('windows') && product.includes('windows')) {
          // Extrair versão do CPE product name
          const cpeWinVer = this.extractWindowsVersionFromCPE(product);
          const detectedWinVer = this.extractWindowsVersions(osLower);
          
          if (cpeWinVer && detectedWinVer.length > 0) {
            if (detectedWinVer.includes(cpeWinVer)) {
              // MATCH! Verificar version ranges do CPE
              if (this.checkCPEVersionRange(cpe, serviceVersion)) {
                return { applies: true, reason: `CPE OS match: ${product} ${version}` };
              }
            } else {
              // Mismatch - acumular mas CONTINUAR procurando
              mismatches.push(`${product}(${cpeWinVer}) != detected(${detectedWinVer.join(',')})`);
            }
          }
        }
      }
      
      // Match de aplicação/serviço (funciona SEM osInfo)
      if (!isOS) {
        foundRelevantCPE = true;
        
        if (serviceVersion) {
          const matches = this.checkCPEVersionRange(cpe, serviceVersion);
          if (matches) {
            // MATCH! Retornar imediatamente
            return { applies: true, reason: `CPE service match: ${vendor}:${product} version ${version}` };
          } else {
            mismatches.push(`${vendor}:${product} ${version} != detected ${serviceVersion}`);
          }
        } else {
          // Sem versão detectada - match se CPE é vulnerável (já verificado no início)
          return { applies: true, reason: `CPE service match (sem versão): ${vendor}:${product}` };
        }
      }
    }
    
    // Se encontramos CPEs relevantes mas NENHUM matched - REJEITAR
    if (foundRelevantCPE && mismatches.length > 0) {
      return { applies: false, reason: `All CPE mismatches: ${mismatches.join('; ')}` };
    }
    
    // Nenhum CPE relevante ao contexto (ex: CVE para Linux mas detectamos Windows)
    return null;
  }

  /**
   * Verifica se uma versão detectada está dentro do range do CPE
   * Normaliza comparações para lidar com build numbers extras
   * Ex: "10.0.19045.452" deve ser <= "10.0.19045"
   */
  private checkCPEVersionRange(cpe: CPEMatch, detectedVersion?: string): boolean {
    if (!detectedVersion) return true; // Sem versão = assume match
    
    const parsed = this.parseVersion(detectedVersion);
    
    // Check versionStartIncluding
    if (cpe.versionStartIncluding) {
      const start = this.parseVersion(cpe.versionStartIncluding);
      // INCLUSIVE: normalizar para comprimento do bound
      if (this.compareVersionsNormalized(parsed, start, false) < 0) {
        return false; // Versão menor que o início do range
      }
    }
    
    // Check versionStartExcluding
    if (cpe.versionStartExcluding) {
      const start = this.parseVersion(cpe.versionStartExcluding);
      // EXCLUSIVE: builds extras contam como > bound
      if (this.compareVersionsNormalized(parsed, start, true) <= 0) {
        return false; // Versão menor ou igual (excluindo)
      }
    }
    
    // Check versionEndIncluding
    if (cpe.versionEndIncluding) {
      const end = this.parseVersion(cpe.versionEndIncluding);
      // INCLUSIVE: normalizar para comprimento do bound
      if (this.compareVersionsNormalized(parsed, end, false) > 0) {
        return false; // Versão maior que o fim do range
      }
    }
    
    // Check versionEndExcluding
    if (cpe.versionEndExcluding) {
      const end = this.parseVersion(cpe.versionEndExcluding);
      // EXCLUSIVE: builds extras contam como > bound
      if (this.compareVersionsNormalized(parsed, end, true) >= 0) {
        return false; // Versão maior ou igual (excluindo)
      }
    }
    
    return true; // Passou todos os checks
  }

  /**
   * Compara versões normalizadas (apenas até o comprimento do bound)
   * Para INCLUSIVE bounds: [10,0,19045,452] vs [10,0,19045] → 0 (iguais)
   * Para EXCLUSIVE bounds: [10,0,19045,452] vs [10,0,19045] → 1 (maior)
   *                        [10,0,19045,0] vs [10,0,19045] → 0 (iguais, trailing zero)
   */
  private compareVersionsNormalized(detected: number[], bound: number[], isExclusive: boolean = false): number {
    // Usar apenas o comprimento do bound para comparação
    const compareLength = bound.length;
    
    for (let i = 0; i < compareLength; i++) {
      const num1 = detected[i] || 0;
      const num2 = bound[i] || 0;
      
      if (num1 < num2) return -1;
      if (num1 > num2) return 1;
    }
    
    // Se iguais até o comprimento do bound:
    // - INCLUSIVE: sempre tratar como iguais (0)
    // - EXCLUSIVE: só maior se detected tem segments extras NON-ZERO
    if (isExclusive && detected.length > bound.length) {
      // Verificar se há algum segment NON-ZERO além do bound
      const hasNonZeroTrailing = detected.slice(compareLength).some(seg => seg !== 0);
      if (hasNonZeroTrailing) {
        // Ex: [10,0,19045,452] > [10,0,19045] para exclusive bounds
        return 1;
      }
      // Ex: [10,0,19045,0] = [10,0,19045] (trailing zeros ignorados)
    }
    
    return 0; // Iguais até o comprimento do bound
  }

  /**
   * Extrai versão do Windows de um CPE product name
   * Ex: "windows_server_2016" -> "2016"
   */
  private extractWindowsVersionFromCPE(product: string): string | null {
    const match = product.match(/windows[_\s]?(?:server[_\s])?(\d{4}|vista|xp|7|8|10|11)/i);
    return match ? match[1] : null;
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
   * Suporta: "1.0 through 2.5", "before 3.0", "prior to 2.1", "< 1.5", "<= 2.0"
   */
  private extractAffectedVersions(description: string): string[] {
    const ranges: string[] = [];
    
    // Padrão 1: "version(s) X through/to Y"
    const rangePattern = /version[s]?\s+([\d.]+)\s+(?:through|to)\s+([\d.]+)/gi;
    for (const match of description.matchAll(rangePattern)) {
      ranges.push(`${match[1]}-${match[2]}`);
    }
    
    // Padrão 2: "before/prior to/earlier than X" -> "0.0-X" (exclusive end)
    const beforePattern = /(?:before|prior\s+to|earlier\s+than|versions?\s+before)\s+([\d.]+)/gi;
    for (const match of description.matchAll(beforePattern)) {
      ranges.push(`<${match[1]}`); // < significa exclusive end
    }
    
    // Padrão 3: "< X" ou "<= X" (símbolos de comparação)
    const lessThanPattern = /(?:version[s]?\s+)?(<|<=)\s*([\d.]+)/gi;
    for (const match of description.matchAll(lessThanPattern)) {
      const operator = match[1];
      const version = match[2];
      ranges.push(operator === '<' ? `<${version}` : `<=${version}`);
    }
    
    // Padrão 4: "> X" ou ">= X" (maior que)
    const greaterThanPattern = /(?:version[s]?\s+)?(>|>=)\s*([\d.]+)/gi;
    for (const match of description.matchAll(greaterThanPattern)) {
      const operator = match[1];
      const version = match[2];
      ranges.push(operator === '>' ? `>${version}` : `>=${version}`);
    }
    
    // Padrão 5: "version X" (versão exata) - só adicionar se não tiver outros ranges
    if (ranges.length === 0) {
      const singlePattern = /version\s+([\d.]+)/gi;
      for (const match of description.matchAll(singlePattern)) {
        ranges.push(match[1]);
      }
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
   * Suporta: "1.0-2.5", "<3.0", "<=2.0", ">1.0", ">=1.5", "2.1" (exata)
   */
  private isVersionInRange(version: number[], range: string): boolean {
    // Range "X-Y" (inclusive)
    if (range.includes('-') && !range.startsWith('<') && !range.startsWith('>')) {
      const [start, end] = range.split('-');
      const startVer = this.parseVersion(start);
      const endVer = this.parseVersion(end);
      
      return this.compareVersions(version, startVer) >= 0 && 
             this.compareVersions(version, endVer) <= 0;
    }
    
    // "< X" (menor que, exclusive)
    if (range.startsWith('<') && !range.startsWith('<=')) {
      const targetVer = this.parseVersion(range.substring(1));
      return this.compareVersions(version, targetVer) < 0;
    }
    
    // "<= X" (menor ou igual)
    if (range.startsWith('<=')) {
      const targetVer = this.parseVersion(range.substring(2));
      return this.compareVersions(version, targetVer) <= 0;
    }
    
    // "> X" (maior que, exclusive)
    if (range.startsWith('>') && !range.startsWith('>=')) {
      const targetVer = this.parseVersion(range.substring(1));
      return this.compareVersions(version, targetVer) > 0;
    }
    
    // ">= X" (maior ou igual)
    if (range.startsWith('>=')) {
      const targetVer = this.parseVersion(range.substring(2));
      return this.compareVersions(version, targetVer) >= 0;
    }
    
    // Versão exata
    const exactVer = this.parseVersion(range);
    return this.compareVersions(version, exactVer) === 0;
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

      // Extrair CPE matches das configurações (fonte confiável de versões afetadas)
      const cpeMatches: CPEMatch[] = [];
      if (cveItem.configurations) {
        for (const config of cveItem.configurations) {
          for (const node of config.nodes) {
            if (node.cpeMatch) {
              cpeMatches.push(...node.cpeMatch);
            }
          }
        }
      }

      return {
        cveId: cveItem.id,
        description: translatedDesc,
        descriptionEnglish: englishDesc.value, // Guardar original para parsing
        severity,
        cvssScore,
        publishedDate: cveItem.published,
        remediation,
        cpeMatches: cpeMatches.length > 0 ? cpeMatches : undefined,
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
