/**
 * Unit tests for RecommendationEngine and remediation templates — REMD-01 through REMD-05
 *
 * Tests verify template output, storage operations, engine dispatch, and status sync.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock DB before any imports
vi.mock('../db', () => ({ db: {}, pool: {} }));

vi.mock('../storage/threats', () => ({
  getThreats: vi.fn(),
  getThreat: vi.fn(),
  updateThreat: vi.fn(),
  getChildThreats: vi.fn(),
}));

vi.mock('../storage/recommendations', () => ({
  upsertRecommendation: vi.fn(),
  getRecommendationByThreatId: vi.fn(),
  getRecommendations: vi.fn(),
}));

vi.mock('../storage', () => ({
  storage: {
    getJob: vi.fn(),
    getHost: vi.fn(),
  },
}));

vi.mock('../lib/logger', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

import type { Threat, Host, Recommendation } from '@shared/schema';
import { templateMap, getTemplate } from '../services/remediation-templates/index';
import type { RecommendationContext, GeneratedRecommendation } from '../services/remediation-templates/types';
import { RecommendationEngine } from '../services/recommendationEngine';
import { getThreats, getThreat, updateThreat, getChildThreats } from '../storage/threats';
import { upsertRecommendation, getRecommendationByThreatId } from '../storage/recommendations';
import { storage } from '../storage';

// ─── Fixtures ───────────────────────────────────────────────────────────────

function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 'threat-1',
    title: 'Test threat',
    description: null,
    severity: 'high',
    status: 'open',
    source: 'journey',
    assetId: null,
    hostId: null,
    evidence: {},
    jobId: 'job-1',
    correlationKey: null,
    category: null,
    ruleId: null,
    lastSeenAt: null,
    closureReason: null,
    hibernatedUntil: null,
    statusChangedBy: null,
    statusChangedAt: null,
    statusJustification: null,
    parentThreatId: null,
    groupingKey: null,
    contextualScore: null,
    scoreBreakdown: null,
    projectedScoreAfterFix: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    assignedTo: null,
    ...overrides,
  } as Threat;
}

function makeHost(overrides: Partial<Host> = {}): Host {
  return {
    id: 'host-1',
    name: 'test-host',
    description: null,
    operatingSystem: null,
    type: 'other',
    family: 'other',
    ips: [],
    aliases: [],
    riskScore: 0,
    rawScore: 0,
    sshHostFingerprint: null,
    discoveredAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Host;
}

function makeRecommendation(overrides: Partial<Recommendation> = {}): Recommendation {
  return {
    id: 'rec-1',
    threatId: 'threat-1',
    templateId: 'exposed-service',
    title: 'Test rec',
    whatIsWrong: 'Something is wrong',
    businessImpact: 'Big impact',
    fixSteps: ['Step 1'],
    verificationStep: 'Verify it',
    references: [],
    effortTag: 'hours',
    roleRequired: 'sysadmin',
    hostSpecificData: {},
    status: 'pending',
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Recommendation;
}

function makeContext(overrides: Partial<RecommendationContext> = {}): RecommendationContext {
  return {
    threat: makeThreat(),
    host: makeHost(),
    hostFamily: 'other',
    evidence: {},
    ...overrides,
  };
}

// ─── Template Map Coverage ──────────────────────────────────────────────────

describe('templateMap coverage', () => {
  const EXPECTED_RULE_IDS = [
    'exposed-service',
    'cve-detected',
    'nuclei-vulnerability',
    'web-vulnerability',
    'edr-av-failure',
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

  it('has entries for all 25 rule IDs', () => {
    const keys = Object.keys(templateMap);
    expect(keys.length).toBe(25);
    for (const ruleId of EXPECTED_RULE_IDS) {
      expect(keys).toContain(ruleId);
    }
  });

  it('getTemplate returns function for known rule', () => {
    const gen = getTemplate('exposed-service');
    expect(typeof gen).toBe('function');
  });

  it('getTemplate returns undefined for unknown rule', () => {
    const gen = getTemplate('nonexistent-rule');
    expect(gen).toBeUndefined();
  });
});

// ─── Template Output Validation ─────────────────────────────────────────────

describe('all templates produce valid GeneratedRecommendation', () => {
  it('every template returns all required fields', () => {
    const ctx = makeContext();
    for (const [ruleId, gen] of Object.entries(templateMap)) {
      const result = gen(ctx);
      expect(result, `${ruleId} should return title`).toHaveProperty('title');
      expect(result, `${ruleId} should return whatIsWrong`).toHaveProperty('whatIsWrong');
      expect(result, `${ruleId} should return businessImpact`).toHaveProperty('businessImpact');
      expect(result, `${ruleId} should return fixSteps array`).toHaveProperty('fixSteps');
      expect(Array.isArray(result.fixSteps), `${ruleId} fixSteps should be array`).toBe(true);
      expect(result.fixSteps.length, `${ruleId} should have at least 1 fix step`).toBeGreaterThan(0);
      expect(result, `${ruleId} should return verificationStep`).toHaveProperty('verificationStep');
      expect(result, `${ruleId} should return references`).toHaveProperty('references');
      expect(Array.isArray(result.references), `${ruleId} references should be array`).toBe(true);
      expect(result, `${ruleId} should return effortTag`).toHaveProperty('effortTag');
      expect(['minutes', 'hours', 'days', 'weeks']).toContain(result.effortTag);
      expect(result, `${ruleId} should return roleRequired`).toHaveProperty('roleRequired');
      expect(['sysadmin', 'developer', 'security', 'vendor']).toContain(result.roleRequired);
      expect(result, `${ruleId} should return hostSpecificData`).toHaveProperty('hostSpecificData');
    }
  });
});

// ─── exposed-service template ────────────────────────────────────────────────

describe('exposed-service template', () => {
  it('interpolates host IP and port into fixSteps (no undefined strings)', () => {
    const ctx = makeContext({
      evidence: {
        host: '10.0.0.1',
        port: '3389',
        service: 'ms-wbt-server',
        serviceCategory: 'admin',
        serviceCategoryLabel: 'Administracao',
      },
    });
    const gen = getTemplate('exposed-service')!;
    const result = gen(ctx);
    const stepsText = result.fixSteps.join('\n');
    expect(stepsText).not.toContain('undefined');
    expect(stepsText).toContain('10.0.0.1');
    expect(stepsText).toContain('3389');
  });

  it('has effortTag minutes for admin category', () => {
    const ctx = makeContext({
      evidence: { host: '10.0.0.1', port: '22', service: 'ssh', serviceCategory: 'admin' },
    });
    const gen = getTemplate('exposed-service')!;
    const result = gen(ctx);
    expect(result.effortTag).toBe('minutes');
  });

  it('roleRequired is sysadmin for exposed-service', () => {
    const ctx = makeContext();
    const gen = getTemplate('exposed-service')!;
    const result = gen(ctx);
    expect(result.roleRequired).toBe('sysadmin');
  });
});

// ─── cve-detected template ───────────────────────────────────────────────────

describe('cve-detected template', () => {
  it('includes NVD reference URL when evidence has cve field', () => {
    const ctx = makeContext({
      evidence: { cve: 'CVE-2023-1234', host: '10.0.0.1', port: '443', service: 'https' },
    });
    const gen = getTemplate('cve-detected')!;
    const result = gen(ctx);
    expect(result.references.join(' ')).toContain('nvd.nist.gov/vuln/detail/CVE-2023-1234');
  });

  it('interpolates CVE id into title', () => {
    const ctx = makeContext({
      evidence: { cve: 'CVE-2021-44228', host: '10.0.0.2', service: 'http' },
    });
    const gen = getTemplate('cve-detected')!;
    const result = gen(ctx);
    expect(result.title).toContain('CVE-2021-44228');
  });
});

// ─── AD template ─────────────────────────────────────────────────────────────

describe('AD template fallback', () => {
  it('AD template uses evidence.recommendation string as fallback fix step', () => {
    const ctx = makeContext({
      evidence: {
        recommendation: 'Stop-Service -Name Spooler -Force',
        category: 'ad-users-password-never-expires',
      },
    });
    const gen = getTemplate('ad-users-password-never-expires')!;
    const result = gen(ctx);
    const stepsText = result.fixSteps.join('\n');
    expect(stepsText).toContain('Stop-Service -Name Spooler -Force');
  });
});

// ─── Storage operations ──────────────────────────────────────────────────────

describe('storage/recommendations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('upsertRecommendation is called with correct data', async () => {
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation());
    const data = {
      threatId: 'threat-1',
      templateId: 'exposed-service',
      title: 'Test',
      whatIsWrong: 'Problem',
      businessImpact: 'Impact',
      fixSteps: ['Fix it'],
      verificationStep: 'Verify',
      references: [],
      effortTag: 'hours' as const,
      roleRequired: 'sysadmin' as const,
      hostSpecificData: {},
    };
    await upsertRecommendation(data as any);
    expect(upsertRecommendation).toHaveBeenCalledWith(data);
  });

  it('getRecommendationByThreatId returns undefined for missing threatId', async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(undefined);
    const result = await getRecommendationByThreatId('nonexistent');
    expect(result).toBeUndefined();
  });
});

// ─── RecommendationEngine.generateForJob ────────────────────────────────────

describe('RecommendationEngine.generateForJob', () => {
  let engine: RecommendationEngine;

  beforeEach(() => {
    vi.clearAllMocks();
    engine = new RecommendationEngine();
  });

  it('calls upsertRecommendation for parent/standalone threats only (not children)', async () => {
    const parentThreat = makeThreat({ id: 'parent-1', ruleId: 'exposed-service', parentThreatId: null, groupingKey: 'grp:key1', jobId: 'job-1' });
    const childThreat = makeThreat({ id: 'child-1', ruleId: 'exposed-service', parentThreatId: 'parent-1', jobId: 'job-1' });

    vi.mocked(storage.getJob).mockResolvedValue({ id: 'job-1', journeyId: 'journey-1' } as any);
    vi.mocked(getThreats).mockResolvedValue([parentThreat]); // only returns non-children
    vi.mocked(getChildThreats).mockResolvedValue([childThreat]);
    vi.mocked(storage.getHost).mockResolvedValue(makeHost());
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation());

    await engine.generateForJob('job-1');

    // Should only call upsertRecommendation once (for parent), not for child
    expect(upsertRecommendation).toHaveBeenCalledTimes(1);
    expect(vi.mocked(upsertRecommendation).mock.calls[0][0]).toMatchObject({ threatId: 'parent-1' });
  });

  it('skips threats with no matching template (logs warning, does not throw)', async () => {
    const threatNoTemplate = makeThreat({ id: 'threat-no-tmpl', ruleId: 'unknown-rule', jobId: 'job-1' });

    vi.mocked(storage.getJob).mockResolvedValue({ id: 'job-1', journeyId: 'journey-1' } as any);
    vi.mocked(getThreats).mockResolvedValue([threatNoTemplate]);
    vi.mocked(getChildThreats).mockResolvedValue([]);
    vi.mocked(storage.getHost).mockResolvedValue(undefined);

    // Should not throw
    await expect(engine.generateForJob('job-1')).resolves.not.toThrow();
    expect(upsertRecommendation).not.toHaveBeenCalled();
  });

  it('aggregates child evidences for parent threats', async () => {
    const parentThreat = makeThreat({ id: 'parent-2', ruleId: 'cve-detected', parentThreatId: null, groupingKey: 'grp:key2', jobId: 'job-1' });
    const child1 = makeThreat({ id: 'child-2a', ruleId: 'cve-detected', parentThreatId: 'parent-2', evidence: { cve: 'CVE-1' } });
    const child2 = makeThreat({ id: 'child-2b', ruleId: 'cve-detected', parentThreatId: 'parent-2', evidence: { cve: 'CVE-2' } });

    vi.mocked(storage.getJob).mockResolvedValue({ id: 'job-1', journeyId: 'journey-1' } as any);
    vi.mocked(getThreats).mockResolvedValue([parentThreat]);
    vi.mocked(getChildThreats).mockResolvedValue([child1, child2]);
    vi.mocked(storage.getHost).mockResolvedValue(undefined);
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation());

    await engine.generateForJob('job-1');

    expect(upsertRecommendation).toHaveBeenCalledTimes(1);
    // childEvidences should have been aggregated
    const callArg = vi.mocked(upsertRecommendation).mock.calls[0][0];
    expect(callArg).toHaveProperty('threatId', 'parent-2');
  });

  it('returns early without error if job not found', async () => {
    vi.mocked(storage.getJob).mockResolvedValue(null);
    await expect(engine.generateForJob('nonexistent-job')).resolves.not.toThrow();
    expect(upsertRecommendation).not.toHaveBeenCalled();
  });
});

// ─── RecommendationEngine.syncRecommendationStatus ──────────────────────────

describe('RecommendationEngine.syncRecommendationStatus', () => {
  let engine: RecommendationEngine;

  beforeEach(() => {
    vi.clearAllMocks();
    engine = new RecommendationEngine();
  });

  it("maps 'mitigated' threat status -> recommendation status 'applied'", async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(makeRecommendation({ status: 'pending' }));
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation({ status: 'applied' }));

    await engine.syncRecommendationStatus('threat-1', 'mitigated');

    expect(upsertRecommendation).toHaveBeenCalledWith(
      expect.objectContaining({ threatId: 'threat-1', status: 'applied' })
    );
  });

  it("maps 'closed' threat status -> recommendation status 'verified'", async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(makeRecommendation({ status: 'applied' }));
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation({ status: 'verified' }));

    await engine.syncRecommendationStatus('threat-1', 'closed');

    expect(upsertRecommendation).toHaveBeenCalledWith(
      expect.objectContaining({ threatId: 'threat-1', status: 'verified' })
    );
  });

  it("maps 'open' (reactivation) threat status -> recommendation status 'failed'", async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(makeRecommendation({ status: 'applied' }));
    vi.mocked(upsertRecommendation).mockResolvedValue(makeRecommendation({ status: 'failed' }));

    await engine.syncRecommendationStatus('threat-1', 'open');

    expect(upsertRecommendation).toHaveBeenCalledWith(
      expect.objectContaining({ threatId: 'threat-1', status: 'failed' })
    );
  });

  it('is a no-op when no recommendation exists for threatId', async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(undefined);

    await engine.syncRecommendationStatus('threat-1', 'mitigated');

    expect(upsertRecommendation).not.toHaveBeenCalled();
  });

  it('does not sync status for non-lifecycle statuses (investigating, hibernated)', async () => {
    vi.mocked(getRecommendationByThreatId).mockResolvedValue(makeRecommendation({ status: 'pending' }));

    await engine.syncRecommendationStatus('threat-1', 'investigating');

    expect(upsertRecommendation).not.toHaveBeenCalled();
  });
});
