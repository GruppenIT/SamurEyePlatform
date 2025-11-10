import type { Credential, JourneyCredential, InsertHostEnrichment } from "@shared/schema";
import { storage } from "../storage";
import { log } from "../vite";

// Types for enrichment data collected from hosts
export interface EnrichmentData {
  hostname?: string; // Real hostname from the machine (not DNS)
  osVersion?: string;
  osBuild?: string;
  installedApps?: Array<{
    name: string;
    version: string;
    vendor?: string;
  }>;
  patches?: string[]; // KB numbers (Windows) or package versions (Linux)
  services?: Array<{
    name: string;
    version?: string;
    port?: number;
  }>;
}

// Interface for host collectors (WMI, SSH, SNMP)
export interface IHostCollector {
  protocol: 'wmi' | 'ssh' | 'snmp';
  
  /**
   * Test if connection can be established with given credential
   * @param host Target host (IP or hostname)
   * @param credential Credential to use for authentication
   * @returns true if connection successful, false otherwise
   */
  testConnection(host: string, credential: Credential): Promise<boolean>;
  
  /**
   * Collect enrichment data from host using credential
   * @param host Target host (IP or hostname)
   * @param credential Credential to use for authentication
   * @returns Enrichment data and audit trail of commands executed
   */
  collectData(host: string, credential: Credential): Promise<{
    data: EnrichmentData;
    commandsExecuted: Array<{
      command: string;
      stdout: string;
      stderr: string;
      exitCode: number;
    }>;
  }>;
}

// Host Enricher orchestrator
export class HostEnricher {
  private collectors: Map<string, IHostCollector> = new Map();
  
  /**
   * Register a collector for a specific protocol
   */
  registerCollector(collector: IHostCollector): void {
    this.collectors.set(collector.protocol, collector);
    log(`[HostEnricher] Registered ${collector.protocol} collector`);
  }
  
  /**
   * Attempt to enrich a host using multiple credentials
   * Implements exponential backoff and stops at first successful credential per protocol
   * 
   * @param hostId Host ID in database
   * @param hostIp Host IP address
   * @param jobId Current job ID
   * @param journeyCredentials List of credentials to try (sorted by priority)
   * @returns Summary of enrichment attempts
   */
  async enrichHost(
    hostId: string,
    hostIp: string,
    jobId: string,
    journeyCredentials: (JourneyCredential & { credential: Credential })[]
  ): Promise<{
    successCount: number;
    failureCount: number;
    enrichments: InsertHostEnrichment[];
  }> {
    const enrichments: InsertHostEnrichment[] = [];
    let successCount = 0;
    let failureCount = 0;
    
    // Group credentials by protocol and sort by priority
    const credentialsByProtocol = new Map<string, (JourneyCredential & { credential: Credential })[]>();
    for (const jc of journeyCredentials) {
      const existing = credentialsByProtocol.get(jc.protocol) || [];
      existing.push(jc);
      credentialsByProtocol.set(jc.protocol, existing);
    }
    
    // Sort each protocol's credentials by priority (ascending = higher priority first)
    const protocolEntries = Array.from(credentialsByProtocol.entries());
    for (const [protocol, creds] of protocolEntries) {
      creds.sort((a, b) => a.priority - b.priority);
      credentialsByProtocol.set(protocol, creds);
    }
    
    // Try each protocol
    const protocolList = Array.from(credentialsByProtocol.entries());
    for (const [protocol, credentials] of protocolList) {
      const collector = this.collectors.get(protocol);
      if (!collector) {
        log(`[HostEnricher] No collector registered for protocol: ${protocol}`, "warn");
        continue;
      }
      
      log(`[HostEnricher] Attempting ${protocol} enrichment for host ${hostIp}`);
      
      // Try credentials in priority order, stop at first success
      let succeeded = false;
      for (const jc of credentials) {
        if (succeeded) break; // Stop at first successful credential for this protocol
        
        try {
          const result = await this.attemptEnrichment(
            hostId,
            hostIp,
            jobId,
            jc.credential,
            collector
          );
          
          enrichments.push(result);
          
          if (result.success) {
            successCount++;
            succeeded = true;
            log(`[HostEnricher] ✓ ${protocol} enrichment successful for ${hostIp} using credential ${jc.credential.name}`);
          } else {
            failureCount++;
            log(`[HostEnricher] ✗ ${protocol} enrichment failed for ${hostIp} using credential ${jc.credential.name}: ${result.errorMessage}`);
          }
        } catch (error) {
          failureCount++;
          const errorMessage = error instanceof Error ? error.message : String(error);
          
          // Log failure and create enrichment record
          log(`[HostEnricher] ✗ ${protocol} enrichment error for ${hostIp}: ${errorMessage}`, "error");
          
          enrichments.push({
            hostId,
            jobId,
            protocol: collector.protocol,
            credentialId: jc.credential.id,
            success: false,
            errorMessage,
            osVersion: null,
            osBuild: null,
            installedApps: null,
            patches: null,
            services: null,
            commandsExecuted: null,
          });
        }
        
        // Exponential backoff between credential attempts
        if (!succeeded && credentials.indexOf(jc) < credentials.length - 1) {
          await this.sleep(1000 * Math.pow(2, credentials.indexOf(jc))); // 1s, 2s, 4s, 8s...
        }
      }
    }
    
    return { successCount, failureCount, enrichments };
  }
  
  /**
   * Attempt single enrichment with timeout and error handling
   */
  private async attemptEnrichment(
    hostId: string,
    hostIp: string,
    jobId: string,
    credential: Credential,
    collector: IHostCollector
  ): Promise<InsertHostEnrichment> {
    const timeout = 30000; // 30 seconds
    
    try {
      // Run collection with timeout
      const result = await Promise.race([
        collector.collectData(hostIp, credential),
        this.timeoutPromise(timeout, `${collector.protocol} collection timeout after ${timeout}ms`),
      ]);
      
      // Validate that we actually collected meaningful data
      const hasData = 
        result.data.osVersion ||
        result.data.osBuild ||
        (result.data.installedApps && result.data.installedApps.length > 0) ||
        (result.data.patches && result.data.patches.length > 0) ||
        (result.data.services && result.data.services.length > 0);
      
      if (!hasData) {
        // No data collected - treat as failure
        return {
          hostId,
          jobId,
          protocol: collector.protocol,
          credentialId: credential.id,
          success: false,
          osVersion: null,
          osBuild: null,
          installedApps: null,
          patches: null,
          services: null,
          commandsExecuted: result.commandsExecuted || null,
          errorMessage: 'No data collected - authentication may have failed or commands returned empty',
        };
      }
      
      // Update host with real hostname if detected
      if (result.data.hostname) {
        try {
          const hosts = await storage.getHosts();
          const host = hosts.find(h => h.id === hostId);
          if (host && host.name !== result.data.hostname.toLowerCase()) {
            const oldName = host.name;
            const newName = result.data.hostname.toLowerCase();
            
            // Add old name to aliases to preserve DNS reverse lookup name
            const existingAliases = host.aliases || [];
            const newAliases = existingAliases.includes(oldName) 
              ? existingAliases 
              : [...existingAliases, oldName];
            
            log(`[HostEnricher] Updating hostname: ${oldName} → ${newName} (old name preserved as alias)`);
            await storage.updateHost(hostId, { 
              name: newName,
              aliases: newAliases 
            });
          }
        } catch (err) {
          log(`[HostEnricher] Failed to update hostname: ${err}`, "warn");
        }
      }
      
      // Success - create enrichment record with real data
      return {
        hostId,
        jobId,
        protocol: collector.protocol,
        credentialId: credential.id,
        success: true,
        osVersion: result.data.osVersion || null,
        osBuild: result.data.osBuild || null,
        installedApps: result.data.installedApps || null,
        patches: result.data.patches || null,
        services: result.data.services || null,
        commandsExecuted: result.commandsExecuted || null,
        errorMessage: null,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Failure - create enrichment record with error
      return {
        hostId,
        jobId,
        protocol: collector.protocol,
        credentialId: credential.id,
        success: false,
        osVersion: null,
        osBuild: null,
        installedApps: null,
        patches: null,
        services: null,
        commandsExecuted: null,
        errorMessage,
      };
    }
  }
  
  /**
   * Helper: create timeout promise
   */
  private timeoutPromise(ms: number, message: string): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error(message)), ms);
    });
  }
  
  /**
   * Helper: sleep for given milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Export singleton instance
export const hostEnricher = new HostEnricher();
