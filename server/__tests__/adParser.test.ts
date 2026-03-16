/**
 * AD parser tests — covers PARS-07, PARS-08, PARS-10
 *
 * Validates that:
 *   - AdFindingSchema accepts correctly shaped objects
 *   - AdFindingSchema rejects invalid objects
 *   - parseAdResults produces typed AdFinding with correct group/GPO/trust mapping
 *   - -Depth 10 note: PowerShell serialization is tested structurally (nested objects/arrays)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { AdFindingSchema, type AdFinding } from '@shared/schema';
import { ADScanner } from '../services/scanners/adScanner';

const fixturesDir = join(__dirname, 'fixtures/ad');

function loadFixture(name: string): any[] {
  const content = readFileSync(join(fixturesDir, name), 'utf-8');
  return JSON.parse(content);
}

const scanner = new ADScanner();

// ──────────────────────────────────────────────────────────────────────────
// AdFindingSchema validation tests (PARS-10)
// ──────────────────────────────────────────────────────────────────────────

describe('AdFindingSchema', () => {
  it('accepts a minimal valid AdFinding', () => {
    const valid = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'medium',
      checkId: 'test_check',
      checkName: 'Test Check',
    };
    const result = AdFindingSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('accepts an AdFinding with all optional fields', () => {
    const full: AdFinding = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'high',
      checkId: 'password_never_expires',
      checkName: 'Password Never Expires',
      details: 'User svc-backup has PasswordNeverExpires=true',
      groupMembership: ['CN=Domain Users,DC=corp,DC=example,DC=com', 'CN=Backup Operators,DC=corp,DC=example,DC=com'],
      gpoLinks: [
        { name: 'Default Domain Policy', path: 'DC=corp,DC=example,DC=com', enabled: true },
      ],
      trustAttributes: {
        direction: 'Bidirecional (Inbound + Outbound)',
        type: 'Forest',
        transitivity: 'Transitive',
      },
      uacFlags: [
        { flag: 'DONT_EXPIRE_PASSWORD', risk: 'Senha nunca expira' },
      ],
      rawData: { Name: 'svc-backup', UserAccountControl: 65536 },
    };
    const result = AdFindingSchema.safeParse(full);
    expect(result.success).toBe(true);
  });

  it('rejects an object missing required "checkId"', () => {
    const invalid = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'medium',
      checkName: 'Test Check',
      // checkId missing
    };
    const result = AdFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects wrong type literal', () => {
    const invalid = {
      type: 'ad_misconfiguration', // wrong — must be 'ad_finding'
      target: 'corp.example.com',
      severity: 'medium',
      checkId: 'test',
      checkName: 'Test',
    };
    const result = AdFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('strips unknown fields via .strip()', () => {
    const withExtra = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'medium',
      checkId: 'test',
      checkName: 'Test',
      unknownField: 'should be stripped',
    };
    const result = AdFindingSchema.safeParse(withExtra);
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as Record<string, unknown>).unknownField).toBeUndefined();
    }
  });

  it('validates groupMembership as ordered string array (PARS-08)', () => {
    const finding = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'medium',
      checkId: 'test',
      checkName: 'Test',
      groupMembership: ['CN=Domain Admins,DC=corp,DC=com', 'CN=Domain Users,DC=corp,DC=com'],
    };
    const result = AdFindingSchema.safeParse(finding);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.groupMembership).toEqual(['CN=Domain Admins,DC=corp,DC=com', 'CN=Domain Users,DC=corp,DC=com']);
      expect(Array.isArray(result.data.groupMembership)).toBe(true);
    }
  });

  it('validates gpoLinks as structured objects (PARS-08)', () => {
    const finding = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'medium',
      checkId: 'test',
      checkName: 'Test',
      gpoLinks: [
        { name: 'Default Domain Policy', path: 'DC=corp,DC=example,DC=com', enabled: true },
        { name: 'Security Baseline', path: 'OU=Servers,DC=corp,DC=example,DC=com' },
      ],
    };
    const result = AdFindingSchema.safeParse(finding);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.gpoLinks).toHaveLength(2);
      expect(result.data.gpoLinks![0].name).toBe('Default Domain Policy');
      expect(result.data.gpoLinks![0].enabled).toBe(true);
      expect(result.data.gpoLinks![1].enabled).toBeUndefined();
    }
  });

  it('validates trustAttributes as typed object (PARS-08)', () => {
    const finding = {
      type: 'ad_finding',
      target: 'corp.example.com',
      severity: 'low',
      checkId: 'trust_relationships',
      checkName: 'Trust Relationships',
      trustAttributes: {
        direction: 'Bidirecional (Inbound + Outbound)',
        type: 'Forest',
        transitivity: 'Transitive',
      },
    };
    const result = AdFindingSchema.safeParse(finding);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trustAttributes?.direction).toBe('Bidirecional (Inbound + Outbound)');
      expect(result.data.trustAttributes?.type).toBe('Forest');
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────
// parseAdResults tests (PARS-07, PARS-08)
// ──────────────────────────────────────────────────────────────────────────

describe('ADScanner.parseAdResults', () => {
  it('returns empty array for empty input', () => {
    const results = scanner.parseAdResults([], 'test_check', 'Test Check');
    expect(results).toEqual([]);
  });

  it('maps raw group membership array to string array (PARS-08)', () => {
    const raw = [
      {
        Name: 'jsmith',
        SamAccountName: 'jsmith',
        MemberOf: [
          'CN=Domain Admins,OU=Groups,DC=corp,DC=com',
          'CN=Domain Users,OU=Groups,DC=corp,DC=com',
        ],
      },
    ];
    const results = scanner.parseAdResults(raw, 'group_membership_check', 'Group Membership Check', 'corp.example.com', 'high');
    expect(results).toHaveLength(1);
    expect(results[0].groupMembership).toBeDefined();
    expect(Array.isArray(results[0].groupMembership)).toBe(true);
    expect(results[0].groupMembership![0]).toBe('CN=Domain Admins,OU=Groups,DC=corp,DC=com');
    expect(results[0].groupMembership![1]).toBe('CN=Domain Users,OU=Groups,DC=corp,DC=com');
  });

  it('maps nested MemberOf objects from -Depth 10 serialization', () => {
    const raw = [
      {
        Name: 'nested-user',
        MemberOf: [
          { DistinguishedName: 'CN=Domain Admins,DC=corp,DC=com', Name: 'Domain Admins' },
        ],
      },
    ];
    const results = scanner.parseAdResults(raw, 'group_membership_check', 'Group Membership Check');
    expect(results[0].groupMembership).toEqual(['CN=Domain Admins,DC=corp,DC=com']);
  });

  it('maps GPO links to structured objects (PARS-08)', () => {
    const raw = [
      {
        Name: 'TestOU',
        LinkedGroupPolicyObjects: [
          { DisplayName: 'Default Domain Policy', Path: 'DC=corp,DC=com', Enabled: true },
        ],
      },
    ];
    const results = scanner.parseAdResults(raw, 'gpo_check', 'GPO Check');
    expect(results[0].gpoLinks).toBeDefined();
    expect(results[0].gpoLinks![0].name).toBe('Default Domain Policy');
    expect(results[0].gpoLinks![0].path).toBe('DC=corp,DC=com');
    expect(results[0].gpoLinks![0].enabled).toBe(true);
  });

  it('maps trust attributes from -Depth 10 output (PARS-08)', () => {
    const raw = [
      {
        Name: 'partner.example.com',
        TrustDirection: 3,
        TrustType: 2,
        ForestTransitive: true,
      },
    ];
    const results = scanner.parseAdResults(raw, 'trust_relationships', 'Trust Relationships');
    expect(results[0].trustAttributes).toBeDefined();
    expect(results[0].trustAttributes!.direction).toContain('Bidirecional');
    expect(results[0].trustAttributes!.transitivity).toBe('Transitive');
  });

  it('decodes UAC flags from userAccountControl value', () => {
    const raw = [
      {
        Name: 'no-expiry-user',
        UserAccountControl: 0x10200, // NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD
      },
    ];
    const results = scanner.parseAdResults(raw, 'password_never_expires', 'Password Never Expires');
    expect(results[0].uacFlags).toBeDefined();
    const flags = results[0].uacFlags!.map(f => f.flag);
    expect(flags).toContain('DONT_EXPIRE_PASSWORD');
  });

  it('preserves rawData for full PS output fallback', () => {
    const raw = [{ Name: 'test-obj', SomeField: 'value', NestedObj: { Key: 'val' } }];
    const results = scanner.parseAdResults(raw, 'test', 'Test');
    expect(results[0].rawData).toBeDefined();
    expect((results[0].rawData as Record<string, unknown>).Name).toBe('test-obj');
  });

  it('skips and logs invalid records without throwing', () => {
    // Null input for an item should be skipped gracefully
    const raw = [null, { Name: 'valid-user' }, undefined];
    expect(() => scanner.parseAdResults(raw as any[], 'test', 'Test')).not.toThrow();
  });

  it('snapshot: parses password-never-expires fixture', () => {
    // password-never-expires.json contains ADFinding shapes (not raw PS output)
    // Use a minimal raw object to test parseAdResults directly
    const raw = [{ Name: 'alice', UserAccountControl: 0x10200 }];
    const results = scanner.parseAdResults(raw, 'password_never_expires', 'Usuários com Senhas que Nunca Expiram', 'corp.example.com', 'medium');
    expect(results).toMatchSnapshot();
    expect(results.every(r => AdFindingSchema.safeParse(r).success)).toBe(true);
  });

  it('snapshot: parses trust relationship raw output with -Depth 10', () => {
    const raw = [
      {
        Name: 'partner.example.com',
        TrustDirection: 3,
        TrustType: 2,
        ForestTransitive: true,
        LinkedGroupPolicyObjects: [],
        MemberOf: [],
      },
    ];
    const results = scanner.parseAdResults(raw, 'trust_relationships', 'Trust Relationships', 'corp.example.com', 'low');
    expect(results).toMatchSnapshot();
    expect(results[0].trustAttributes).toBeDefined();
  });
});
