import { storage } from '../storage';
import { type InsertHost, type Host } from '@shared/schema';

// Type aliases for enum values
type HostType = 'server' | 'desktop' | 'firewall' | 'switch' | 'router' | 'domain' | 'other';
type HostFamily = 'linux' | 'windows_server' | 'windows_desktop' | 'fortios' | 'network_os' | 'other';

export interface HostDiscoveryResult {
  name: string;
  description?: string;
  operatingSystem?: string;
  type: HostType;
  family: HostFamily;
  ips: string[];
  aliases?: string[];
}

class HostService {
  /**
   * Normalizes a host name by converting to lowercase and removing common prefixes
   */
  private normalizeHostName(name: string): string {
    let normalized = name.toLowerCase().trim();
    
    // Remove common prefixes like "www.", "ftp.", etc. for better deduplication
    const prefixPatterns = [
      /^www\./,
      /^ftp\./,
      /^mail\./,
      /^smtp\./,
      /^pop3?\./,
      /^imap\./,
    ];
    
    for (const pattern of prefixPatterns) {
      normalized = normalized.replace(pattern, '');
    }
    
    return normalized;
  }

  /**
   * Determines host type based on discovered information
   */
  private determineHostType(findings: any[]): HostType {
    // Normalize ports to numbers for consistent comparison
    const ports = findings.map(f => Number(f.port)).filter(p => !isNaN(p));
    const services = findings.map(f => (f.service || '').toLowerCase()).filter(Boolean);
    const banners = findings.map(f => (f.banner || '').toLowerCase()).filter(Boolean);
    
    // Check for firewall indicators
    const hasFirewallIndicators = findings.some(f => 
      banners.some(b => b.includes('fortios') || b.includes('fortigate') || b.includes('pfsense') || b.includes('cisco asa')) ||
      services.some(s => s.includes('ike') || s.includes('ipsec'))
    );
    
    if (hasFirewallIndicators) {
      return 'firewall';
    }
    
    // Check for network device indicators
    const hasNetworkIndicators = findings.some(f => 
      ports.includes(161) || // SNMP
      banners.some(b => b.includes('cisco ios') || b.includes('junos') || b.includes('juniper') || b.includes('hp procurve') || b.includes('netgear')) ||
      services.some(s => s.includes('snmp') || s.includes('lldp') || s.includes('cdp'))
    );
    
    if (hasNetworkIndicators) {
      // Try to distinguish router vs switch
      const hasRoutingServices = findings.some(f => 
        banners.some(b => b.includes('router') || b.includes('routing')) ||
        services.some(s => s.includes('bgp') || s.includes('ospf'))
      );
      return hasRoutingServices ? 'router' : 'switch';
    }

    // Check for domain controller indicators
    const hasDomainServices = findings.some(f => 
      services.includes('ldap') || 
      services.includes('kerberos') || 
      ports.includes(389) || 
      ports.includes(636) || 
      ports.includes(88)
    );
    
    if (hasDomainServices) {
      return 'server';
    }

    // Check for server indicators (including Windows Server services)
    const hasServerServices = findings.some(f => 
      services.some(s => 
        s.includes('http') || s.includes('ssh') || s.includes('ftp') || 
        s.includes('smtp') || s.includes('dns') || s.includes('ms-sql') ||
        s.includes('mssql') || s.includes('sql server') || s.includes('iis') ||
        s.includes('ms-wbt-server') // Terminal Services on Windows Server
      ) ||
      ports.some(p => [80, 443, 22, 21, 25, 53, 8080, 8443, 1433, 1434].includes(p)) // Include SQL Server ports
    );
    
    // Check for Windows Server specific indicators in banners
    const hasWindowsServerBanners = banners.some(b => 
      b.includes('windows server') || b.includes('microsoft sql server') ||
      b.includes('terminal services') || b.includes('microsoft iis')
    );
    
    if (hasServerServices || hasWindowsServerBanners) {
      return 'server';
    }

    // Check for desktop/workstation indicators (only if not server)
    const hasWorkstationServices = findings.some(f => 
      services.some(s => s.includes('microsoft-ds') || s.includes('netbios')) ||
      ports.some(p => [445, 139].includes(p))
    ) && !hasServerServices && !hasWindowsServerBanners;
    
    // RDP alone doesn't determine desktop vs server, check context
    const hasRDP = findings.some(f => 
      services.some(s => s.includes('rdp')) || ports.includes(3389)
    );
    
    if (hasWorkstationServices && !hasServerServices && !hasWindowsServerBanners) {
      return 'desktop';
    }

    // Default to server if we have any services
    return findings.length > 0 ? 'server' : 'other';
  }

  /**
   * Determines host family based on OS information and services
   */
  private determineHostFamily(findings: any[], osInfo?: string, hostType?: HostType): HostFamily {
    const osLower = (osInfo || '').toLowerCase();
    const services = findings.map(f => (f.service || '').toLowerCase()).filter(Boolean);
    const banners = findings.map(f => (f.banner || '').toLowerCase()).filter(Boolean);
    const ports = findings.map(f => Number(f.port)).filter(p => !isNaN(p));
    
    // Check for FortiOS first (specific network OS)
    if (banners.some(b => b.includes('fortios') || b.includes('fortigate'))) {
      return 'fortios';
    }
    
    // Check for other network OS
    if (banners.some(b => b.includes('cisco ios') || b.includes('junos') || b.includes('juniper'))) {
      return 'network_os';
    }
    
    // Check OS info first
    if (osLower.includes('windows')) {
      // Distinguish desktop vs server based on OS string or host type
      if (osLower.includes('professional') || osLower.includes('home') || osLower.includes('workstation') || hostType === 'desktop') {
        return 'windows_desktop';
      }
      return 'windows_server';
    }
    
    if (osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian') || osLower.includes('centos') || osLower.includes('redhat') || osLower.includes('fedora') || osLower.includes('suse')) {
      return 'linux';
    }
    
    if (osLower.includes('unix') || osLower.includes('solaris') || osLower.includes('aix') || osLower.includes('freebsd') || osLower.includes('openbsd')) {
      return 'other';
    }
    
    // Check services for OS hints
    const hasWindowsServices = findings.some(f => 
      services.some(s => s.includes('microsoft') || s.includes('iis') || s.includes('rdp') || s.includes('netbios')) ||
      ports.some(p => [3389, 445, 139, 135].includes(p))
    );
    
    if (hasWindowsServices) {
      // If it's desktop type or has desktop-like services, classify as windows_desktop
      if (hostType === 'desktop' || ports.includes(3389)) {
        return 'windows_desktop';
      }
      return 'windows_server';
    }

    const hasLinuxServices = findings.some(f => 
      services.some(s => s.includes('ssh') || s.includes('apache') || s.includes('nginx') || s.includes('postfix')) ||
      ports.includes(22)
    );
    
    if (hasLinuxServices) {
      return 'linux';
    }

    return 'other';
  }

  /**
   * Discovers hosts from scan findings and creates/updates them in the database
   */
  async discoverHostsFromFindings(findings: any[], jobId: string): Promise<Host[]> {
    const discoveredHosts = new Map<string, HostDiscoveryResult>();
    
    // Group findings by target (IP or hostname)
    const targetGroups = new Map<string, any[]>();
    
    for (const finding of findings) {
      const target = finding.target || finding.ip || finding.host;
      if (!target) continue;
      
      if (!targetGroups.has(target)) {
        targetGroups.set(target, []);
      }
      targetGroups.get(target)!.push(finding);
    }

    // Process each target group to create host discovery results
    for (const [target, targetFindings] of Array.from(targetGroups)) {
      const hostResult = await this.createHostFromTarget(target, targetFindings);
      if (hostResult) {
        // Enhanced deduplication: check existing hosts by name AND by IP overlap
        await this.deduplicateAndMergeHost(discoveredHosts, hostResult);
      }
    }

    // Create/update hosts in database
    const hosts: Host[] = [];
    for (const hostResult of Array.from(discoveredHosts.values())) {
      try {
        const host = await storage.upsertHost(hostResult);
        hosts.push(host);
        console.log(`🏠 Host descoberto/atualizado: ${host.name} (${host.ips.join(', ')})`);
      } catch (error) {
        console.error(`❌ Erro ao salvar host ${hostResult.name}:`, error);
      }
    }

    return hosts;
  }

  /**
   * Creates a host discovery result from a target and its findings
   */
  private async createHostFromTarget(target: string, findings: any[]): Promise<HostDiscoveryResult | null> {
    // Determine if target is IP or hostname
    const isIpAddress = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    
    let name = target.toLowerCase(); // Always normalize to lowercase
    let ips: string[] = [];
    let aliases: string[] = [];
    
    if (isIpAddress) {
      ips.push(target);
      // Try to find hostname from findings
      const hostnames = findings
        .map(f => f.hostname || f.host)
        .filter(h => h && h !== target && !/^\d+\.\d+\.\d+\.\d+$/.test(h));
      
      // Remove duplicates from hostnames
      const uniqueHostnames = Array.from(new Set(hostnames));
      
      if (uniqueHostnames.length > 0) {
        name = uniqueHostnames[0].toLowerCase();
        aliases = uniqueHostnames.slice(1).map(h => h.toLowerCase());
      } else {
        name = `host-${target.replace(/\./g, '-')}`;
      }
    } else {
      // Target is hostname - find actual IPs from findings
      const foundIps = findings
        .map(f => f.ip)
        .filter(ip => ip && ip !== target && /^\d+\.\d+\.\d+\.\d+$/.test(ip));
      
      // Remove duplicates - each port scan creates a finding with the same IP
      ips = Array.from(new Set(foundIps)); // Only actual IPs, never hostnames - can be empty array
      
      // Find other hostnames as aliases
      const otherHostnames = findings
        .map(f => f.hostname || f.host)
        .filter(h => h && h !== target && !/^\d+\.\d+\.\d+\.\d+$/.test(h))
        .map(h => h.toLowerCase());
      
      // Remove duplicates from aliases
      aliases = Array.from(new Set(otherHostnames));
    }

    // Get OS information
    const osInfo = findings
      .map(f => f.osInfo || f.os || f.operatingSystem)
      .filter(Boolean)[0];

    // Determine type and family
    const type = this.determineHostType(findings);
    const family = this.determineHostFamily(findings, osInfo, type);
    
    // Apply normalization to the actual saved name too
    const normalizedSavedName = this.normalizeHostName(name);

    return {
      name: normalizedSavedName, // Fully normalized name for persistence
      description: `Host descoberto via scan (Job ID: ${this.getShortJobId(findings[0]?.jobId || '')})`,
      operatingSystem: osInfo,
      type,
      family,
      ips,
      aliases: aliases.length > 0 ? aliases : undefined,
    };
  }

  /**
   * Creates a special domain host for AD Hygiene journeys
   */
  async createDomainHost(domainName: string, jobId: string): Promise<Host> {
    const domainHost: InsertHost = {
      name: domainName.toLowerCase(),
      description: `Domínio Active Directory (Job ID: ${this.getShortJobId(jobId)})`,
      type: 'domain' as HostType,
      family: 'windows_server' as HostFamily,
      ips: [], // Domains don't have direct IPs
      aliases: [],
    };

    const host = await storage.upsertHost(domainHost);
    console.log(`🏠 Host de domínio criado/atualizado: ${host.name}`);
    return host;
  }

  /**
   * Finds existing hosts that match the given criteria
   */
  async findHostsByTarget(target: string): Promise<Host[]> {
    const isIpAddress = /^\d+\.\d+\.\d+\.\d+$/.test(target);
    
    if (isIpAddress) {
      // Search by IP
      const host = await storage.findHostByTarget(target);
      return host ? [host] : [];
    } else {
      // Search by name first
      let host = await storage.getHostByName(target.toLowerCase());
      
      // If not found by name, search in aliases (for renamed hosts)
      if (!host) {
        host = await storage.findHostByTarget(target.toLowerCase());
      }
      
      return host ? [host] : [];
    }
  }

  /**
   * Gets host statistics for dashboard
   */
  async getHostStatistics(): Promise<{
    totalHosts: number;
    byType: Record<HostType, number>;
    byFamily: Record<HostFamily, number>;
    recentlyDiscovered: number; // Last 7 days
  }> {
    const hosts = await storage.getHosts();
    
    const stats = {
      totalHosts: hosts.length,
      byType: {} as Record<HostType, number>,
      byFamily: {} as Record<HostFamily, number>,
      recentlyDiscovered: 0,
    };

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    for (const host of hosts) {
      // Count by type
      stats.byType[host.type] = (stats.byType[host.type] || 0) + 1;
      
      // Count by family
      stats.byFamily[host.family] = (stats.byFamily[host.family] || 0) + 1;
      
      // Count recently discovered
      if (host.discoveredAt && host.discoveredAt > sevenDaysAgo) {
        stats.recentlyDiscovered++;
      }
    }

    return stats;
  }

  /**
   * Enhanced deduplication that checks for overlapping IPs and merges hosts appropriately
   */
  private async deduplicateAndMergeHost(discoveredHosts: Map<string, HostDiscoveryResult>, newHost: HostDiscoveryResult): Promise<void> {
    const normalizedName = this.normalizeHostName(newHost.name);
    
    // First check if we have the same normalized name
    if (discoveredHosts.has(normalizedName)) {
      const existing = discoveredHosts.get(normalizedName)!;
      this.mergeHostResults(existing, newHost);
      return;
    }
    
    // Check for IP overlap with any existing hosts
    for (const [existingKey, existingHost] of Array.from(discoveredHosts)) {
      const hasIpOverlap = newHost.ips.some(ip => existingHost.ips.includes(ip));
      
      if (hasIpOverlap) {
        // Same machine discovered with different names - merge
        console.log(`🔄 Merging hosts by IP overlap: ${existingHost.name} + ${newHost.name}`);
        this.mergeHostResults(existingHost, newHost);
        return;
      }
    }
    
    // No duplicates found, add as new
    discoveredHosts.set(normalizedName, newHost);
  }

  /**
   * Merges two host results, combining their data intelligently
   */
  private mergeHostResults(existing: HostDiscoveryResult, newHost: HostDiscoveryResult): void {
    // Merge IPs
    existing.ips = Array.from(new Set([...existing.ips, ...newHost.ips]));
    
    // Merge aliases
    if (newHost.aliases) {
      existing.aliases = Array.from(new Set([...(existing.aliases || []), ...newHost.aliases]));
    }
    
    // Add the new host's name as an alias if different
    if (newHost.name !== existing.name && !existing.aliases?.includes(newHost.name)) {
      existing.aliases = existing.aliases || [];
      existing.aliases.push(newHost.name);
    }
    
    // Prefer more specific OS information
    if (newHost.operatingSystem && !existing.operatingSystem) {
      existing.operatingSystem = newHost.operatingSystem;
    }
    
    // Prefer more specific type/family if current is 'other'
    if (newHost.type !== 'other' && existing.type === 'other') {
      existing.type = newHost.type;
    }
    if (newHost.family !== 'other' && existing.family === 'other') {
      existing.family = newHost.family;
    }
  }

  /**
   * Gets a shortened version of job ID for display
   */
  private getShortJobId(jobId: string): string {
    return jobId ? jobId.slice(-8) : 'unknown';
  }
}

export const hostService = new HostService();