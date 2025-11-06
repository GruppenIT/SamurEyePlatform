import { Client } from 'ssh2';
import type { Credential } from "@shared/schema";
import type { IHostCollector, EnrichmentData } from "../hostEnricher";
import { log } from "../../vite";

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
      data.patches = data.installedApps.map(app => `${app.name}:${app.version}`);

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
      data.patches = data.installedApps.map(app => `${app.name}:${app.version}`);
    } else {
      log(`[SSHCollector] Unsupported or unknown package manager: ${packageManager}`, "warn");
    }

    // 3. Get running services (systemctl for systemd-based systems)
    const servicesResult = await this.executeSSH(
      host,
      credential,
      'systemctl list-units --type=service --state=running --no-legend --no-pager | awk \'{print $1}\'',
      'Get Running Services'
    );
    commandsExecuted.push({
      command: 'systemctl list-units --type=service --state=running',
      stdout: servicesResult.stdout,
      stderr: servicesResult.stderr,
      exitCode: servicesResult.exitCode,
    });

    if (servicesResult.success && servicesResult.stdout) {
      const serviceNames = servicesResult.stdout.trim().split('\n').filter(s => s.trim());
      data.services = serviceNames.map(name => ({
        name: name.replace('.service', ''),
        version: undefined,
        port: undefined,
      }));
      
      log(`[SSHCollector] Found ${data.services.length} running services`);
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
        const { decryptCredentialPassword } = require('../credentialService');
        password = decryptCredentialPassword(credential);
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
