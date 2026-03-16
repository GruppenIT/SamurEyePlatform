/**
 * nmap parser tests — covers PARS-01, PARS-03, PARS-04, PARS-10
 *
 * Test structure:
 *   Task 1: Schema validation unit tests (NmapFindingSchema safeParse)
 *   Task 2: parseNmapXml snapshot tests against 8 synthetic fixture files
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { NmapFindingSchema, NmapVulnFindingSchema } from '@shared/schema';
import { NetworkScanner } from '../services/scanners/networkScanner';

const fixturesDir = join(__dirname, 'fixtures/nmap');

// ────────────────────────────────────────────────────────────────
// Task 1: Schema validation tests (RED — schemas do not exist yet)
// ────────────────────────────────────────────────────────────────

describe('NmapFindingSchema', () => {
  it('accepts a valid NmapFinding with all required fields', () => {
    const valid = {
      type: 'port',
      target: '192.168.1.1',
      severity: 'medium',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
    };
    const result = NmapFindingSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('accepts a NmapFinding with all optional fields populated', () => {
    const full = {
      type: 'port',
      target: '192.168.1.1',
      severity: 'high',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
      ip: '192.168.1.1',
      product: 'Microsoft Windows',
      version: '10',
      extrainfo: 'workgroup: WORKGROUP',
      serviceCpe: 'cpe:/o:microsoft:windows_10',
      osName: 'Windows 10',
      osAccuracy: 98,
      osCpe: ['cpe:/o:microsoft:windows_10'],
      nseScripts: [
        { id: 'smb-security-mode', output: 'Message signing disabled' },
      ],
      banner: 'some banner',
      osInfo: 'Windows 10',
      timestamp: new Date().toISOString(),
    };
    const result = NmapFindingSchema.safeParse(full);
    expect(result.success).toBe(true);
  });

  it('rejects an object missing required field "port"', () => {
    const invalid = {
      type: 'port',
      target: '192.168.1.1',
      severity: 'medium',
      state: 'open',
      service: 'microsoft-ds',
      // port is missing
    };
    const result = NmapFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects an object with wrong type literal', () => {
    const invalid = {
      type: 'vuln', // wrong — must be "port"
      target: '192.168.1.1',
      severity: 'medium',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
    };
    const result = NmapFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects an object with invalid severity value', () => {
    const invalid = {
      type: 'port',
      target: '192.168.1.1',
      severity: 'extreme', // not in enum
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
    };
    const result = NmapFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('strips unknown fields via .strip()', () => {
    const withExtra = {
      type: 'port',
      target: '192.168.1.1',
      severity: 'medium',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
      unknownField: 'should be stripped',
    };
    const result = NmapFindingSchema.safeParse(withExtra);
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as Record<string, unknown>).unknownField).toBeUndefined();
    }
  });
});

describe('NmapVulnFindingSchema', () => {
  it('accepts a valid NmapVulnFinding with type "nmap_vuln"', () => {
    const valid = {
      type: 'nmap_vuln',
      target: '192.168.1.1',
      severity: 'critical',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
    };
    const result = NmapVulnFindingSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('rejects type "port" for NmapVulnFindingSchema', () => {
    const invalid = {
      type: 'port', // wrong — must be "nmap_vuln"
      target: '192.168.1.1',
      severity: 'critical',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
    };
    const result = NmapVulnFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────
// Task 2: parseNmapXml snapshot tests
// ────────────────────────────────────────────────────────────────

describe('NetworkScanner.parseNmapXml', () => {
  const scanner = new NetworkScanner();

  it('smb-open-no-vuln: parses single host with SMB port open', () => {
    const xml = readFileSync(join(fixturesDir, 'smb-open-no-vuln.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.10');
    expect(findings.length).toBe(1);
    expect(findings[0].port).toBe('445');
    expect(findings[0].state).toBe('open');
    expect(findings[0].service).toBe('microsoft-ds');
    expect(findings).toMatchSnapshot();
  });

  it('rdp-with-os-detection: populates osName, osAccuracy, osCpe from XML', () => {
    const xml = readFileSync(join(fixturesDir, 'rdp-with-os-detection.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.20');
    expect(findings.length).toBe(1);
    expect(findings[0].port).toBe('3389');
    expect(findings[0].osName).toBe('Windows Server 2019');
    expect(findings[0].osAccuracy).toBe(98);
    expect(findings[0].osCpe).toContain('cpe:/o:microsoft:windows_server_2019');
    expect(findings).toMatchSnapshot();
  });

  it('vuln-ms17-010: captures NSE script with CVE reference', () => {
    const xml = readFileSync(join(fixturesDir, 'vuln-ms17-010.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.1');
    expect(findings.length).toBe(1);
    expect(findings[0].nseScripts).toBeDefined();
    expect(findings[0].nseScripts!.length).toBeGreaterThan(0);
    expect(findings[0].nseScripts![0].id).toBe('smb-vuln-ms17-010');
    expect(findings).toMatchSnapshot();
  });

  it('multi-host-cidr: returns findings for all 3 hosts open ports', () => {
    const xml = readFileSync(join(fixturesDir, 'multi-host-cidr.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.0/24');
    // host1: 2 open, host2: 1 open (8080 is filtered), host3: 2 open = 5 total
    expect(findings.length).toBe(5);
    // All findings must pass schema validation
    findings.forEach(f => {
      expect(NmapFindingSchema.safeParse(f).success).toBe(true);
    });
    expect(findings).toMatchSnapshot();
  });

  it('single-host-all-fields: populates OS, service version, and NSE script fields', () => {
    const xml = readFileSync(join(fixturesDir, 'single-host-all-fields.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.50');
    const smb = findings.find(f => f.port === '445');
    expect(smb).toBeDefined();
    expect(smb!.product).toBeDefined();
    expect(smb!.osName).toBe('Windows Server 2019');
    expect(smb!.nseScripts).toBeDefined();
    expect(findings).toMatchSnapshot();
  });

  it('filtered-ports-only: returns empty array (no open ports)', () => {
    const xml = readFileSync(join(fixturesDir, 'filtered-ports-only.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.99');
    expect(findings).toHaveLength(0);
  });

  it('os-detection-cpe: populates osCpe array from multiple osclass elements', () => {
    const xml = readFileSync(join(fixturesDir, 'os-detection-cpe.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.11');
    expect(findings.length).toBe(1);
    expect(findings[0].osCpe).toBeDefined();
    expect(findings[0].osCpe!.length).toBeGreaterThan(1);
    expect(findings[0].osCpe).toContain('cpe:/o:linux:linux_kernel:5.15');
    expect(findings).toMatchSnapshot();
  });

  it('service-version-cpe: populates product, version, extrainfo, serviceCpe fields', () => {
    const xml = readFileSync(join(fixturesDir, 'service-version-cpe.xml'), 'utf-8');
    const findings = scanner.parseNmapXml(xml, '192.168.1.60');
    const mssql = findings.find(f => f.port === '1433');
    expect(mssql).toBeDefined();
    expect(mssql!.product).toBe('Microsoft SQL Server');
    expect(mssql!.version).toBe('2019');
    expect(mssql!.extrainfo).toBeDefined();
    expect(mssql!.serviceCpe).toBe('cpe:/a:microsoft:sql_server:2019');
    expect(findings).toMatchSnapshot();
  });

  it('malformed XML: returns empty array and does not throw', () => {
    const findings = scanner.parseNmapXml('this is not xml', '192.168.1.1');
    expect(findings).toHaveLength(0);
  });

  it('empty string: returns empty array', () => {
    const findings = scanner.parseNmapXml('', '192.168.1.1');
    expect(findings).toHaveLength(0);
  });
});
