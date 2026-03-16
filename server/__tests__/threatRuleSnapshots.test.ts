/**
 * Threat rule snapshot tests — covers PARS-11
 *
 * For each of the 25 threat engine rules, this test:
 *   1. Loads the relevant fixture
 *   2. Parses it through the appropriate parser
 *   3. Finds the rule by ID in the threat engine
 *   4. Asserts the rule's matcher returns true
 *   5. Snapshots the createThreat output (the data contract)
 *
 * These snapshots lock the data contract between parsers and threat engine.
 * A snapshot update signals a breaking change in parser output or rule logic.
 *
 * NOTE: We test the rule logic directly (matcher + createThreat) without
 * going through storage, to avoid database dependencies in unit tests.
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// Mock database and storage to avoid DATABASE_URL requirement
vi.mock('../db', () => ({ db: {}, pool: {} }));
vi.mock('../storage', () => ({ storage: {} }));
vi.mock('./hostService', () => ({ hostService: {} }));
vi.mock('../services/hostService', () => ({ hostService: {} }));
vi.mock('../services/notificationService', () => ({ notificationService: {} }));

import { threatEngine } from '../services/threatEngine';
import { NetworkScanner } from '../services/scanners/networkScanner';
import { EdrFindingSchema } from '@shared/schema';

const nmapFixturesDir = join(__dirname, 'fixtures/nmap');
const nucleiFixturesDir = join(__dirname, 'fixtures/nuclei');
const adFixturesDir = join(__dirname, 'fixtures/ad');
const edrFixturesDir = join(__dirname, 'fixtures/edr');

const networkScanner = new NetworkScanner();

// ─── helpers ────────────────────────────────────────────────────────────────

function loadJson(dir: string, name: string): any {
  return JSON.parse(readFileSync(join(dir, name), 'utf-8'));
}

function loadText(dir: string, name: string): string {
  return readFileSync(join(dir, name), 'utf-8');
}

/**
 * Find a rule by ID and verify it matches the given finding, then snapshot createThreat output.
 */
function testRule(ruleId: string, finding: any, label?: string): void {
  const rules = threatEngine.getRules();
  const rule = rules.find(r => r.id === ruleId);
  if (!rule) {
    throw new Error(`Rule '${ruleId}' not found in threat engine`);
  }
  expect(rule.matcher(finding)).toBeTruthy();
  const threat = rule.createThreat(finding, undefined, 'test-job-id');
  expect(threat).toMatchSnapshot(`${ruleId}${label ? ':' + label : ''}`);
}

// ─── Nmap rules ─────────────────────────────────────────────────────────────

describe('nmap rules', () => {
  it('exposed-service: smb port triggers rule', () => {
    const xml = loadText(nmapFixturesDir, 'smb-open-no-vuln.xml');
    const findings = networkScanner.parseNmapXml(xml, '192.168.1.10');
    const smbFinding = findings.find(f => f.port === '445');
    expect(smbFinding).toBeDefined();
    testRule('exposed-service', smbFinding!);
  });

  it('cve-detected: nmap_vuln finding with CVE triggers rule', () => {
    // Build a minimal nmap_vuln finding that the cve-detected rule matches
    const nvulnFinding = {
      type: 'nmap_vuln',
      target: '192.168.1.1',
      severity: 'critical',
      port: '445',
      state: 'open',
      service: 'microsoft-ds',
      cve: 'CVE-2017-0144',
      description: 'EternalBlue vulnerability',
    };
    testRule('cve-detected', nvulnFinding);
  });
});

// ─── Nuclei rules ────────────────────────────────────────────────────────────

describe('nuclei rules', () => {
  it('nuclei-vulnerability: vulnerability finding from nuclei scan triggers rule', () => {
    // nuclei-vulnerability rule matches type === 'vulnerability' with evidence.source === 'nuclei'
    // This is the internal format produced by vulnScanner.parseNucleiOutput (used during actual scan),
    // not the public parseNuclei() which outputs NucleiFinding with type 'nuclei'
    const cveContent = loadText(nucleiFixturesDir, 'cve-with-classification.jsonl');
    const line = JSON.parse(cveContent.trim().split('\n')[0]);
    const templateId = line['template-id'] || line.templateID || line.template;
    const finding = {
      type: 'vulnerability',
      target: 'https://target.example.com',
      name: line.info?.name || templateId,
      severity: 'critical',
      template: templateId,
      description: line.info?.description || '',
      evidence: {
        source: 'nuclei',
        templateId,
        url: line['matched-at'],
        matcher: line['matcher-name'],
        extractedResults: line['extracted-results'],
        curl: line['curl-command'],
        info: line.info,
      },
    };
    testRule('nuclei-vulnerability', finding);
  });

  it('web-vulnerability: web_vulnerability type triggers rule', () => {
    // web-vulnerability rule matches type === 'web_vulnerability'
    const webVulnFinding = {
      type: 'web_vulnerability',
      target: 'https://example.com',
      severity: 'medium',
      name: 'X-Frame-Options Missing',
      description: 'The X-Frame-Options header is not set',
      port: '443',
      service: 'https',
      template: 'missing-x-frame-options',
      evidence: { host: 'example.com', port: '443' },
    };
    testRule('web-vulnerability', webVulnFinding);
  });
});

// ─── EDR rules ───────────────────────────────────────────────────────────────

describe('EDR rules', () => {
  it('edr-av-failure: detection-failure fixture triggers edr-av-failure rule', () => {
    const raw = loadJson(edrFixturesDir, 'detection-failure.json');
    const parsed = EdrFindingSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    const finding = parsed.data!;
    testRule('edr-av-failure', finding);
  });

  it('edr-av-failure: detection-success does NOT trigger rule (eicarRemoved=true)', () => {
    const raw = loadJson(edrFixturesDir, 'detection-success.json');
    const finding = EdrFindingSchema.safeParse(raw).data!;
    const rules = threatEngine.getRules();
    const rule = rules.find(r => r.id === 'edr-av-failure')!;
    // EDR success (eicarRemoved=true) should NOT match
    expect(rule.matcher(finding)).toBe(false);
  });
});

// ─── AD rules ────────────────────────────────────────────────────────────────

describe('AD rules', () => {
  it('ad-security-generic: ad_misconfiguration type triggers generic rule', () => {
    const findings = loadJson(adFixturesDir, 'generic-ad-finding.json');
    const genericFinding = findings.find((f: any) => f.type === 'ad_misconfiguration' && f.name === 'Print Spooler Habilitado em DC');
    expect(genericFinding).toBeDefined();
    testRule('ad-security-generic', genericFinding);
  });

  it('ad-users-password-never-expires: matching finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'password-never-expires.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-users-password-never-expires', findings[0]);
  });

  it('ad-domain-controller-not-found: dc not found finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'domain-controller-not-found.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-domain-controller-not-found', findings[0]);
  });

  it('ad-inactive-users: inactive users finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'inactive-users.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-inactive-users', findings[0]);
  });

  it('ad-users-old-passwords: old passwords finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'old-passwords.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-users-old-passwords', findings[0]);
  });

  it('ad-privileged-group-members: privileged group finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'privileged-group-members.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-privileged-group-members', findings[0]);
  });

  it('ad-obsolete-os: obsolete OS finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'obsolete-os.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-obsolete-os', findings[0]);
  });

  it('ad-inactive-computers: inactive computers finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'inactive-computers.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-inactive-computers', findings[0]);
  });

  it('ad-weak-password-policy: weak password policy finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'weak-password-policy.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('ad-weak-password-policy', findings[0]);
  });

  it('domain-admin-critical-password-expired: critical domain admin finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'domain-admin-critical.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('domain-admin-critical-password-expired', findings[0]);
  });

  it('specific-inactive-user: specific inactive user finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'specific-inactive-user.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('specific-inactive-user', findings[0]);
  });

  it('privileged-group-too-many-members: too many members finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'privileged-group-too-many.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('privileged-group-too-many-members', findings[0]);
  });

  it('password-complexity-disabled: complexity disabled finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'password-complexity-disabled.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('password-complexity-disabled', findings[0]);
  });

  it('password-history-insufficient: insufficient history finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'password-history-insufficient.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('password-history-insufficient', findings[0]);
  });

  it('passwords-never-expire: passwords never expire policy finding triggers rule', () => {
    const allFindings = loadJson(adFixturesDir, 'generic-ad-finding.json');
    const finding = allFindings.find((f: any) => f.name === 'Senhas Sem Expiração');
    expect(finding).toBeDefined();
    testRule('passwords-never-expire', finding);
  });

  it('inactive-computer-detected: specific inactive computer finding triggers rule', () => {
    const allFindings = loadJson(adFixturesDir, 'generic-ad-finding.json');
    const finding = allFindings.find((f: any) => f.name === 'Computador Inativo no Domínio');
    expect(finding).toBeDefined();
    testRule('inactive-computer-detected', finding);
  });

  it('obsolete-operating-system: specific obsolete OS finding triggers rule', () => {
    const allFindings = loadJson(adFixturesDir, 'generic-ad-finding.json');
    const finding = allFindings.find((f: any) => f.name === 'Sistema Operacional Obsoleto');
    expect(finding).toBeDefined();
    testRule('obsolete-operating-system', finding);
  });

  it('bidirectional-trust-detected: bidirectional trust finding triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'bidirectional-trust.json');
    expect(findings.length).toBeGreaterThan(0);
    testRule('bidirectional-trust-detected', findings[0]);
  });

  it('domain-admin-old-password: domain admin with old password triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'password-never-expires-user.json');
    const domainAdminFinding = findings.find((f: any) =>
      f.type === 'ad_user' &&
      Array.isArray(f.groups) &&
      f.groups.includes('Domain Admins') &&
      f.passwordAge > 90
    );
    expect(domainAdminFinding).toBeDefined();
    testRule('domain-admin-old-password', domainAdminFinding);
  });

  it('password-never-expires: account with passwordNeverExpires=true triggers rule', () => {
    const findings = loadJson(adFixturesDir, 'password-never-expires-user.json');
    const neverExpiresFinding = findings.find((f: any) =>
      f.type === 'ad_user' && f.passwordNeverExpires === true
    );
    expect(neverExpiresFinding).toBeDefined();
    testRule('password-never-expires', neverExpiresFinding);
  });
});

// ─── Rule count verification ─────────────────────────────────────────────────

describe('threat rule coverage', () => {
  it('threat engine has at least 25 rules', () => {
    const rules = threatEngine.getRules();
    expect(rules.length).toBeGreaterThanOrEqual(25);
  });

  it('all 25 required rule IDs exist in the threat engine', () => {
    const requiredRuleIds = [
      // Nmap rules
      'exposed-service',
      'cve-detected',
      // Nuclei rules
      'nuclei-vulnerability',
      'web-vulnerability',
      // EDR rules
      'edr-av-failure',
      // AD rules (20)
      'ad-security-generic',
      'ad-users-password-never-expires',
      'ad-domain-controller-not-found',
      'ad-inactive-users',
      'ad-users-old-passwords',
      'ad-privileged-group-members',
      'ad-obsolete-os',
      'ad-inactive-computers',
      'ad-weak-password-policy',
      'domain-admin-critical-password-expired',
      'specific-inactive-user',
      'privileged-group-too-many-members',
      'password-complexity-disabled',
      'password-history-insufficient',
      'passwords-never-expire',
      'inactive-computer-detected',
      'obsolete-operating-system',
      'bidirectional-trust-detected',
      'domain-admin-old-password',
      'password-never-expires',
    ];

    const existingRuleIds = threatEngine.getRules().map(r => r.id);
    for (const id of requiredRuleIds) {
      expect(existingRuleIds, `Rule '${id}' should exist`).toContain(id);
    }
  });
});
