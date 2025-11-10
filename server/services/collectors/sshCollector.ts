import { Client } from 'ssh2';
import type { Credential } from "@shared/schema";
import type { IHostCollector, EnrichmentData } from "../hostEnricher";
import { log } from "../../vite";
import { encryptionService } from "../encryption";

/**
 * SSH Collector for Linux/Unix hosts
 * Uses ssh2 library to execute commands via SSH
 */
export class SSHCollector implements IHostCollector {
  protocol: 'wmi' | 'ssh' | 'snmp' = 'ssh';

  /**
   * Test SSH connection to host
   */
  async testConnection(host: string, credential: Credential): Promise<boolean> {
    try {
      const result = await this.executeSSH(host, credential, 'echo test', 'Connection Test');
      return result.success && result.stdout.trim() === 'test';
    } catch (error) {
      log(`[SSHCollector] Connection test failed for ${host}: ${error}`, "error");
      return false;
    }
  }

  /**
   * Collect enrichment data from Linux/Unix host
   */
  async collectData(host: string, credential: Credential): Promise<{
    data: EnrichmentData;
    commandsExecuted: Array<{
      command: string;
      stdout: string;
      stderr: string;
      exitCode: number;
    }>;
  }> {
    const commandsExecuted: Array<{
      command: string;
      stdout: string;
      stderr: string;
      exitCode: number;
    }> = [];

    const data: EnrichmentData = {
      installedApps: [],
      patches: [],
      services: [],
    };

    // 1. Get OS information (uname -a)
    const osResult = await this.executeSSH(host, credential, 'uname -s -r -v', 'Get OS Info');
    commandsExecuted.push({
      command: 'uname -s -r -v',
      stdout: osResult.stdout,
      stderr: osResult.stderr,
      exitCode: osResult.exitCode,
    });

    if (osResult.success && osResult.stdout) {
      const parts = osResult.stdout.trim().split(' ');
      data.osVersion = parts[0] || 'Linux'; // Linux, Darwin, etc.
      data.osBuild = parts.slice(1).join(' '); // Kernel version + details
      
      log(`[SSHCollector] OS detected: ${data.osVersion} ${data.osBuild}`);
    }

    // 2. Detect package manager and get installed packages
    const pmDetectResult = await this.executeSSH(
      host,
      credential,
      'command -v dpkg || command -v rpm || command -v pacman || echo none',
      'Detect Package Manager'
    );
    
    const packageManager = pmDetectResult.stdout.trim().split('/').pop()?.trim() || 'none';
    log(`[SSHCollector] Detected package manager: ${packageManager}`);

    if (packageManager === 'dpkg') {
      // Debian/Ubuntu
      const pkgsResult = await this.executeSSH(
        host,
        credential,
        'dpkg-query -W -f=\'${Package}|${Version}|${Maintainer}\\n\' | head -1000',
        'Get Installed Packages (dpkg)'
      );
      commandsExecuted.push({
        command: 'dpkg-query -W',
        stdout: pkgsResult.stdout,
        stderr: pkgsResult.stderr,
        exitCode: pkgsResult.exitCode,
      });

      if (pkgsResult.success && pkgsResult.stdout) {
        const lines = pkgsResult.stdout.trim().split('\n');
        data.installedApps = lines.map(line => {
          const [name, version, vendor] = line.split('|');
          return {
            name: name?.trim() || '',
            version: version?.trim() || '',
            vendor: vendor?.trim() || '',
          };
        }).filter(app => app.name);
        
        log(`[SSHCollector] Found ${data.installedApps.length} packages (dpkg)`);
      }

      // Get patches (dpkg list with dates) - store package names as "patches"
      data.patches = data.installedApps?.map(app => `${app.name}:${app.version}`) || [];

    } else if (packageManager === 'rpm') {
      // RHEL/CentOS/Fedora
      const pkgsResult = await this.executeSSH(
        host,
        credential,
        'rpm -qa --qf "%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}\\n" | head -1000',
        'Get Installed Packages (rpm)'
      );
      commandsExecuted.push({
        command: 'rpm -qa',
        stdout: pkgsResult.stdout,
        stderr: pkgsResult.stderr,
        exitCode: pkgsResult.exitCode,
      });

      if (pkgsResult.success && pkgsResult.stdout) {
        const lines = pkgsResult.stdout.trim().split('\n');
        data.installedApps = lines.map(line => {
          const [name, version, vendor] = line.split('|');
          return {
            name: name?.trim() || '',
            version: version?.trim() || '',
            vendor: vendor?.trim() || '',
          };
        }).filter(app => app.name);
        
        log(`[SSHCollector] Found ${data.installedApps.length} packages (rpm)`);
      }

      // Get patches - store package names as "patches"
      data.patches = data.installedApps?.map(app => `${app.name}:${app.version}`) || [];
    } else {
      log(`[SSHCollector] Unsupported or unknown package manager: ${packageManager}`, "warn");
    }

    // 3. Get all services with detailed information (systemctl for systemd-based systems)
    // First, get list of services with their status
    const servicesResult = await this.executeSSH(
      host,
      credential,
      'systemctl list-units --all --type=service --no-pager --no-legend --plain --full',
      'Get All Services'
    );
    commandsExecuted.push({
      command: 'systemctl list-units --all --type=service',
      stdout: servicesResult.stdout,
      stderr: servicesResult.stderr,
      exitCode: servicesResult.exitCode,
    });

    if (servicesResult.success && servicesResult.stdout) {
      const lines = servicesResult.stdout.trim().split('\n').filter(s => s.trim());
      const serviceUnits: string[] = [];
      
      // Parse systemctl output: UNIT LOAD ACTIVE SUB DESCRIPTION
      const parsedServices = lines.map(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) return null;
        
        const unit = parts[0]; // e.g., "cron.service"
        const loadState = parts[1]; // e.g., "loaded"
        const activeState = parts[2]; // e.g., "active"
        const subState = parts[3]; // e.g., "running"
        const description = parts.slice(4).join(' '); // e.g., "Regular background program processing daemon"
        
        const name = unit.replace('.service', '');
        serviceUnits.push(unit); // Keep full unit name for systemctl is-enabled
        
        // Map systemd active state to status
        const status = activeState === 'active' ? 'Running' : 
                       activeState === 'inactive' ? 'Stopped' : 
                       activeState === 'failed' ? 'Failed' : 
                       activeState || 'Unknown';
        
        return {
          name,
          displayName: description || name,
          loadState,
          activeState,
          status,
          description: description || '',
        };
      }).filter(svc => svc !== null);
      
      // Get enablement status for all services (this determines startType)
      const enabledResult = await this.executeSSH(
        host,
        credential,
        `systemctl is-enabled ${serviceUnits.join(' ')} 2>/dev/null || true`,
        'Get Service Enablement'
      );
      commandsExecuted.push({
        command: 'systemctl is-enabled (batch)',
        stdout: enabledResult.stdout,
        stderr: enabledResult.stderr,
        exitCode: enabledResult.exitCode,
      });
      
      // Parse enablement results (one per line, in same order as serviceUnits)
      const enabledStates = enabledResult.success && enabledResult.stdout 
        ? enabledResult.stdout.trim().split('\n')
        : [];
      
      // Combine service data with enablement status
      data.services = parsedServices.map((svc, idx) => {
        const enabledState = enabledStates[idx]?.trim() || 'unknown';
        
        // Map systemd enablement to startup type
        let startType = 'Manual';
        if (enabledState === 'enabled' || enabledState === 'static' || enabledState === 'indirect') {
          startType = 'Automático';
        } else if (enabledState === 'disabled') {
          startType = 'Desabilitado';
        } else if (enabledState === 'masked') {
          startType = 'Desabilitado';
        }
        
        return {
          name: svc.name,
          displayName: svc.displayName,
          startType,
          status: svc.status,
          description: svc.description,
        };
      });
      
      log(`[SSHCollector] Found ${data.services.length} services`);
    }

    return { data, commandsExecuted };
  }

  /**
   * Execute command via SSH
   */
  private async executeSSH(
    host: string,
    credential: Credential,
    command: string,
    testName?: string
  ): Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
  }> {
    return new Promise((resolve) => {
      const conn = new Client();
      let stdout = '';
      let stderr = '';
      let exitCode = 0;

      // Decrypt password
      let password: string;
      try {
        password = encryptionService.decryptCredential(credential.secretEncrypted, credential.dekEncrypted);
      } catch (error) {
        log(`[SSHCollector] Failed to decrypt password: ${error}`, "error");
        return resolve({
          success: false,
          stdout: '',
          stderr: `Failed to decrypt password: ${error}`,
          exitCode: -1,
        });
      }

      const port = credential.port || 22;

      const timeout = setTimeout(() => {
        conn.end();
        resolve({
          success: false,
          stdout,
          stderr: 'SSH connection timeout (30s)',
          exitCode: -1,
        });
      }, 30000); // 30s timeout

      conn.on('ready', () => {
        if (testName) {
          log(`[SSHCollector] Executing: ${testName}`);
        }

        conn.exec(command, (err, stream) => {
          if (err) {
            clearTimeout(timeout);
            conn.end();
            return resolve({
              success: false,
              stdout: '',
              stderr: `SSH exec error: ${err.message}`,
              exitCode: -1,
            });
          }

          stream.on('close', (code: number) => {
            clearTimeout(timeout);
            conn.end();
            exitCode = code;
            resolve({
              success: code === 0,
              stdout,
              stderr,
              exitCode: code,
            });
          });

          stream.on('data', (data: Buffer) => {
            stdout += data.toString('utf8');
          });

          stream.stderr.on('data', (data: Buffer) => {
            stderr += data.toString('utf8');
          });
        });
      });

      conn.on('error', (err) => {
        clearTimeout(timeout);
        log(`[SSHCollector] Connection error: ${err.message}`, "error");
        resolve({
          success: false,
          stdout: '',
          stderr: `SSH connection error: ${err.message}`,
          exitCode: -1,
        });
      });

      // Connect
      conn.connect({
        host,
        port,
        username: credential.username,
        password,
        readyTimeout: 30000,
      });
    });
  }
}
