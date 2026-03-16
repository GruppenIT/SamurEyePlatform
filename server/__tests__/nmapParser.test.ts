/**
 * nmap parser tests — covers PARS-01, PARS-03, PARS-04, PARS-10
 *
 * Test structure: RED tests first (Task 1), then snapshot tests (Task 2)
 */
import { describe, it, expect } from 'vitest';
import { NmapFindingSchema, NmapVulnFindingSchema } from '@shared/schema';

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
