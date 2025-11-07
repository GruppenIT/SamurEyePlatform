import { spawn } from 'child_process';
import type { Credential } from "@shared/schema";
import type { IHostCollector, EnrichmentData } from "../hostEnricher";
import { log } from "../../vite";
import { encryptionService } from "../encryption";

/**
 * WMI Collector for Windows hosts
 * Uses pywinrm wrapper to execute PowerShell commands via WinRM
 */
export class WMICollector implements IHostCollector {
  protocol: 'wmi' | 'ssh' | 'snmp' = 'wmi';

  /**
   * Test WinRM connection to host
   */
  async testConnection(host: string, credential: Credential): Promise<boolean> {
    try {
      // Simple connection test: query hostname
      const result = await this.executePowerShell(host, credential, 'hostname', 'Connection Test');
      return result.success && result.stdout.trim().length > 0;
    } catch (error) {
      log(`[WMICollector] Connection test failed for ${host}: ${error}`, "error");
      return false;
    }
  }

  /**
   * Collect enrichment data from Windows host
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

    // 1. Get OS information (Get-ComputerInfo)
    const osScript = `
      $info = Get-ComputerInfo -Property WindowsProductName,WindowsVersion,WindowsBuildLabEx,OsHardwareAbstractionLayer
      $obj = @{
        ProductName = $info.WindowsProductName
        Version = $info.WindowsVersion
        BuildLabEx = $info.WindowsBuildLabEx
        HAL = $info.OsHardwareAbstractionLayer
      }
      $obj | ConvertTo-Json -Compress
    `;

    const osResult = await this.executePowerShell(host, credential, osScript, 'Get-ComputerInfo');
    commandsExecuted.push({
      command: 'Get-ComputerInfo',
      stdout: osResult.stdout,
      stderr: osResult.stderr,
      exitCode: osResult.exitCode,
    });

    if (osResult.success && osResult.stdout) {
      try {
        const osInfo = JSON.parse(osResult.stdout);
        data.osVersion = osInfo.ProductName || '';
        data.osBuild = osInfo.BuildLabEx || osInfo.Version || '';
        
        log(`[WMICollector] OS detected: ${data.osVersion} (${data.osBuild})`);
      } catch (e) {
        log(`[WMICollector] Failed to parse OS info: ${e}`, "warn");
      }
    }

    // 2. Get installed applications (Get-WmiObject Win32_Product - limited, so we also check registry)
    const appsScript = `
      # Get apps from Win32_Product (slower but reliable)
      $apps = @()
      
      # Registry-based detection (faster, covers more apps)
      $paths = @(
        'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
      )
      
      foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
          $apps += @{
            Name = $_.DisplayName
            Version = $_.DisplayVersion
            Vendor = $_.Publisher
          }
        }
      }
      
      # Limit to 500 apps to avoid huge payloads
      $apps | Select-Object -First 500 | ConvertTo-Json -Compress
    `;

    const appsResult = await this.executePowerShell(host, credential, appsScript, 'Get Installed Applications');
    commandsExecuted.push({
      command: 'Get Installed Applications',
      stdout: appsResult.stdout,
      stderr: appsResult.stderr,
      exitCode: appsResult.exitCode,
    });

    if (appsResult.success && appsResult.stdout) {
      try {
        const apps = JSON.parse(appsResult.stdout);
        data.installedApps = Array.isArray(apps) ? apps.map((app: any) => ({
          name: app.Name || '',
          version: app.Version || '',
          vendor: app.Vendor || app.Publisher || '',
        })) : (apps.Name ? [{
          name: apps.Name,
          version: apps.Version || '',
          vendor: apps.Vendor || apps.Publisher || '',
        }] : []);
        
        log(`[WMICollector] Found ${data.installedApps.length} installed applications`);
      } catch (e) {
        log(`[WMICollector] Failed to parse apps: ${e}`, "warn");
      }
    }

    // 3. Get installed patches (Get-HotFix)
    const patchesScript = `
      Get-HotFix | Select-Object -ExpandProperty HotFixID | ConvertTo-Json -Compress
    `;

    const patchesResult = await this.executePowerShell(host, credential, patchesScript, 'Get-HotFix');
    commandsExecuted.push({
      command: 'Get-HotFix',
      stdout: patchesResult.stdout,
      stderr: patchesResult.stderr,
      exitCode: patchesResult.exitCode,
    });

    if (patchesResult.success && patchesResult.stdout) {
      try {
        const patches = JSON.parse(patchesResult.stdout);
        data.patches = Array.isArray(patches) ? patches : (patches ? [patches] : []);
        
        log(`[WMICollector] Found ${data.patches.length} installed patches (KBs)`);
      } catch (e) {
        log(`[WMICollector] Failed to parse patches: ${e}`, "warn");
      }
    }

    // 4. Get running services
    const servicesScript = `
      Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name,DisplayName | ConvertTo-Json -Compress
    `;

    const servicesResult = await this.executePowerShell(host, credential, servicesScript, 'Get-Service');
    commandsExecuted.push({
      command: 'Get-Service',
      stdout: servicesResult.stdout,
      stderr: servicesResult.stderr,
      exitCode: servicesResult.exitCode,
    });

    if (servicesResult.success && servicesResult.stdout) {
      try {
        const services = JSON.parse(servicesResult.stdout);
        data.services = Array.isArray(services) ? services.map((svc: any) => ({
          name: svc.Name || '',
          version: undefined,
          port: undefined,
        })) : (services.Name ? [{
          name: services.Name,
          version: undefined,
          port: undefined,
        }] : []);
        
        log(`[WMICollector] Found ${data.services.length} running services`);
      } catch (e) {
        log(`[WMICollector] Failed to parse services: ${e}`, "warn");
      }
    }

    return { data, commandsExecuted };
  }

  /**
   * Execute PowerShell command via WinRM using Python wrapper
   */
  private async executePowerShell(
    host: string,
    credential: Credential,
    script: string,
    testName?: string
  ): Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
  }> {
    return new Promise((resolve) => {
      // Detect paths for virtualenv and wrapper
      const installDir = process.env.INSTALL_DIR || process.cwd();
      const venvPath = process.env.VENV_PATH || `${installDir}/venv`;
      const pythonBin = `${venvPath}/bin/python`;
      const wrapperPath = `${installDir}/server/utils/winrm-wrapper.py`;

      // Decrypt credential password
      let password: string;
      try {
        password = encryptionService.decryptCredential(credential.secretEncrypted, credential.dekEncrypted);
      } catch (error) {
        log(`[WMICollector] Failed to decrypt password: ${error}`, "error");
        return resolve({
          success: false,
          stdout: '',
          stderr: `Failed to decrypt password: ${error}`,
          exitCode: -1,
        });
      }

      // Format username (add domain if not present)
      let username = credential.username;
      if (credential.domain && !username.includes('\\') && !username.includes('@')) {
        username = `${credential.domain}\\${username}`;
      }

      // Log command details
      const cmdArgs = [
        wrapperPath,
        '--host', host,
        '--username', username,
        '--script', script,
        '--timeout', '30',
        '--password-stdin'
      ];
      log(`[WMICollector] Executing: ${pythonBin} ${cmdArgs.join(' ').replace(password, '[REDACTED]')}`);
      log(`[WMICollector] Credential: username="${username}", domain="${credential.domain || '(empty)'}", port=${credential.port || 5985}`);

      // Execute wrapper
      const winrm = spawn(pythonBin, cmdArgs);

      // Error handler
      winrm.on('error', (error) => {
        log(`[WMICollector] Error executing wrapper: ${error.message}`, "error");
        resolve({
          success: false,
          stdout: '',
          stderr: `Error executing WinRM wrapper: ${error.message}`,
          exitCode: -1,
        });
      });

      // Send password via stdin
      try {
        winrm.stdin.write(password + '\n');
        winrm.stdin.end();
      } catch (e) {
        log(`[WMICollector] Error sending password via stdin: ${e}`, "error");
      }

      let stdout = '';
      let stderr = '';

      winrm.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      winrm.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      winrm.on('close', (code) => {
        // Parse JSON response from wrapper
        try {
          if (stdout.trim()) {
            const parsed = JSON.parse(stdout);
            const success = parsed.exitCode === 0;
            
            if (testName) {
              log(`[WMICollector] PowerShell [${testName}]: exitCode=${parsed.exitCode}${!success ? ` (stderr: ${parsed.stderr?.substring(0, 100)})` : ''}`);
            }
            
            resolve({
              success,
              stdout: parsed.stdout || '',
              stderr: parsed.stderr || parsed.error || '',
              exitCode: parsed.exitCode || 0,
            });
          } else {
            log(`[WMICollector] No JSON output from wrapper. Python exitCode=${code}, stderr=${stderr.substring(0, 200)}`, "error");
            resolve({
              success: false,
              stdout: '',
              stderr: stderr || 'No output from wrapper',
              exitCode: code || 1,
            });
          }
        } catch (e) {
          log(`[WMICollector] Failed to parse wrapper JSON. stdout=${stdout.substring(0, 200)}, stderr=${stderr.substring(0, 200)}`, "error");
          resolve({
            success: false,
            stdout: stdout,
            stderr: stderr || `Failed to parse wrapper response: ${e}`,
            exitCode: code || 1,
          });
        }
      });
    });
  }
}
