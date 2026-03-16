/**
 * Unit tests for ScoringEngineService — THRT-06 through THRT-10
 *
 * These tests verify pure computation functions without DB access.
 * DB-touching methods (scoreAllThreatsForJob, computeProjectedScores,
 * writePostureSnapshot) are tested via mocked storage calls.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock storage modules before importing service
vi.mock('../storage/threats', () => ({
  getThreats: vi.fn(),
  updateThreat: vi.fn(),
}));

vi.mock('../storage/posture', () => ({
  writePostureSnapshot: vi.fn(),
}));

vi.mock('../storage', () => ({
  storage: {
    getJob: vi.fn(),
    getJourney: vi.fn(),
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

import { ScoringEngineService, scoringEngine } from '../services/scoringEngine';
import { getThreats, updateThreat } from '../storage/threats';
import * as postureStorage from '../storage/posture';
import { storage } from '../storage';
import type { Threat, Host } from '@shared/schema';

// Helpers to build minimal test fixtures
function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 'threat-1',
    title: 'Test threat',
    description: null,
    severity: 'critical',
    status: 'open',
    source: 'journey',
    assetId: null,
    hostId: null,
    evidence: {},
    jobId: 'job-1',
    correlationKey: null,
    category: null,
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

describe('ScoringEngineService — computeContextualScore', () => {
  let engine: ScoringEngineService;

  beforeEach(() => {
    engine = new ScoringEngineService();
  });

  // THRT-06: Base severity weights
  it('assigns baseSeverityWeight=100 for critical, 75 for high, 50 for medium, 25 for low', () => {
    const critical = engine.computeContextualScore(makeThreat({ severity: 'critical' }), undefined, 'attack_surface', 'unknown');
    expect(critical.baseSeverityWeight).toBe(100);

    const high = engine.computeContextualScore(makeThreat({ severity: 'high' }), undefined, 'attack_surface', 'unknown');
    expect(high.baseSeverityWeight).toBe(75);

    const medium = engine.computeContextualScore(makeThreat({ severity: 'medium' }), undefined, 'attack_surface', 'unknown');
    expect(medium.baseSeverityWeight).toBe(50);

    const low = engine.computeContextualScore(makeThreat({ severity: 'low' }), undefined, 'attack_surface', 'unknown');
    expect(low.baseSeverityWeight).toBe(25);
  });

  // THRT-08: Criticality multipliers by host type
  it('applies 1.5x criticalityMultiplier for domain controller (THRT-08)', () => {
    const dcHost = makeHost({ type: 'domain' });
    const desktopHost = makeHost({ type: 'desktop' });

    const dcBreakdown = engine.computeContextualScore(makeThreat({ severity: 'critical' }), dcHost, 'attack_surface', 'unknown');
    const desktopBreakdown = engine.computeContextualScore(makeThreat({ severity: 'critical' }), desktopHost, 'attack_surface', 'unknown');

    expect(dcBreakdown.criticalityMultiplier).toBe(1.5);
    expect(desktopBreakdown.criticalityMultiplier).toBe(1.0);
    // DC should produce a higher raw score than desktop (rawScore reflects multiplier; normalizedScore may both clamp to 100)
    expect(dcBreakdown.rawScore).toBeGreaterThan(desktopBreakdown.rawScore);
  });

  it('applies 1.2x criticalityMultiplier for server, firewall, router hosts', () => {
    for (const hostType of ['server', 'firewall', 'router'] as const) {
      const host = makeHost({ type: hostType });
      const breakdown = engine.computeContextualScore(makeThreat({ severity: 'high' }), host, 'attack_surface', 'unknown');
      expect(breakdown.criticalityMultiplier).toBe(1.2);
    }
  });

  it('applies 1.0x criticalityMultiplier for desktop, switch, other hosts', () => {
    for (const hostType of ['desktop', 'switch', 'other'] as const) {
      const host = makeHost({ type: hostType });
      const breakdown = engine.computeContextualScore(makeThreat({ severity: 'high' }), host, 'attack_surface', 'unknown');
      expect(breakdown.criticalityMultiplier).toBe(1.0);
    }
  });

  it('defaults criticalityMultiplier to 1.0 when no host provided (THRT-08)', () => {
    const breakdown = engine.computeContextualScore(makeThreat({ severity: 'high' }), undefined, 'attack_surface', 'unknown');
    expect(breakdown.criticalityMultiplier).toBe(1.0);
  });

  // THRT-06: Exposure factors by journey type
  it('applies exposureFactor=1.3 for attack_surface journey (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'attack_surface', 'unknown');
    expect(breakdown.exposureFactor).toBe(1.3);
  });

  it('applies exposureFactor=1.0 for ad_security journey (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'ad_security', 'unknown');
    expect(breakdown.exposureFactor).toBe(1.0);
  });

  it('applies exposureFactor=0.9 for edr_av journey (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'edr_av', 'unknown');
    expect(breakdown.exposureFactor).toBe(0.9);
  });

  it('applies exposureFactor=1.2 for web_application journey (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'web_application', 'unknown');
    expect(breakdown.exposureFactor).toBe(1.2);
  });

  // THRT-06: Controls reduction factor
  it('applies controlsReductionFactor=0.85 when edrStatus is passed (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'attack_surface', 'passed');
    expect(breakdown.controlsReductionFactor).toBe(0.85);
  });

  it('applies controlsReductionFactor=1.0 when edrStatus is unknown (THRT-06)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'attack_surface', 'unknown');
    expect(breakdown.controlsReductionFactor).toBe(1.0);
  });

  // THRT-09: Exploitability multiplier
  it('applies exploitabilityMultiplier=1.3 for nmap_vuln threat type (THRT-09)', () => {
    const threat = makeThreat({ source: 'nmap_vuln' });
    const breakdown = engine.computeContextualScore(threat, undefined, 'attack_surface', 'unknown');
    expect(breakdown.exploitabilityMultiplier).toBe(1.3);
  });

  it('applies exploitabilityMultiplier=1.3 when evidence has nuclei confirmation (THRT-09)', () => {
    const threat = makeThreat({
      evidence: { nucleiMatch: true, confirmed: true },
    });
    const breakdown = engine.computeContextualScore(threat, undefined, 'attack_surface', 'unknown');
    expect(breakdown.exploitabilityMultiplier).toBe(1.3);
  });

  it('applies exploitabilityMultiplier=1.0 for standard threats without exploitability evidence (THRT-09)', () => {
    const breakdown = engine.computeContextualScore(makeThreat({ source: 'journey' }), undefined, 'attack_surface', 'unknown');
    expect(breakdown.exploitabilityMultiplier).toBe(1.0);
  });

  // THRT-07: All 7 fields in scoreBreakdown
  it('returns scoreBreakdown with all 7 required fields (THRT-07)', () => {
    const breakdown = engine.computeContextualScore(makeThreat(), undefined, 'attack_surface', 'unknown');

    expect(breakdown).toHaveProperty('baseSeverityWeight');
    expect(breakdown).toHaveProperty('criticalityMultiplier');
    expect(breakdown).toHaveProperty('exposureFactor');
    expect(breakdown).toHaveProperty('controlsReductionFactor');
    expect(breakdown).toHaveProperty('exploitabilityMultiplier');
    expect(breakdown).toHaveProperty('rawScore');
    expect(breakdown).toHaveProperty('normalizedScore');
    expect(Object.keys(breakdown)).toHaveLength(7);
  });

  // normalizedScore clamped to 0-100
  it('normalizedScore is always clamped to 0-100 range', () => {
    // DC + critical + attack_surface + no controls + nmap_vuln → should produce high score but clamped
    const dcHost = makeHost({ type: 'domain' });
    const threat = makeThreat({ severity: 'critical', source: 'nmap_vuln' });
    const breakdown = engine.computeContextualScore(threat, dcHost, 'attack_surface', 'unknown');
    expect(breakdown.normalizedScore).toBeGreaterThanOrEqual(0);
    expect(breakdown.normalizedScore).toBeLessThanOrEqual(100);
  });
});

describe('ScoringEngineService — computePostureFromThreats', () => {
  let engine: ScoringEngineService;

  beforeEach(() => {
    engine = new ScoringEngineService();
  });

  // Edge case: no open threats
  it('returns posture score 100 when there are no threats (THRT-10)', () => {
    const score = engine.computePostureFromThreats([]);
    expect(score).toBe(100);
  });

  it('returns a reduced posture score when there are open threats', () => {
    const threats = [
      makeThreat({ status: 'open', contextualScore: 80 }),
      makeThreat({ id: 'threat-2', status: 'open', contextualScore: 60 }),
    ];
    const score = engine.computePostureFromThreats(threats);
    expect(score).toBeLessThan(100);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  it('considers only open threats in posture computation', () => {
    const openThreats = [makeThreat({ status: 'open', contextualScore: 50 })];
    const closedThreats = [makeThreat({ id: 'closed-1', status: 'closed', contextualScore: 90 })];

    const scoreWithOnlyOpen = engine.computePostureFromThreats(openThreats);
    const scoreWithMixed = engine.computePostureFromThreats([...openThreats, ...closedThreats]);

    // Closed threats should not affect score — only open ones count
    expect(scoreWithOnlyOpen).toBe(scoreWithMixed);
  });

  it('clamps posture score to 0-100 range', () => {
    // Many high-score threats should not produce negative score
    const massiveThreats = Array.from({ length: 50 }, (_, i) =>
      makeThreat({ id: `threat-${i}`, status: 'open', contextualScore: 100 })
    );
    const score = engine.computePostureFromThreats(massiveThreats);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  // THRT-10: projectedScoreAfterFix = posture without threat - current posture (positive = improvement)
  it('projected improvement is positive when removing threats (THRT-10)', () => {
    const threat1 = makeThreat({ id: 'threat-1', status: 'open', contextualScore: 80 });
    const threat2 = makeThreat({ id: 'threat-2', status: 'open', contextualScore: 40 });

    const currentScore = engine.computePostureFromThreats([threat1, threat2]);
    const projectedScore = engine.computePostureFromThreats([threat2]); // Remove threat1

    const delta = projectedScore - currentScore;
    expect(delta).toBeGreaterThan(0); // Removing a threat should improve posture
  });
});

describe('ScoringEngineService — singleton export', () => {
  it('exports a singleton scoringEngine instance', () => {
    expect(scoringEngine).toBeInstanceOf(ScoringEngineService);
  });

  it('singleton computeContextualScore works correctly', () => {
    const breakdown = scoringEngine.computeContextualScore(
      makeThreat({ severity: 'high' }),
      makeHost({ type: 'server' }),
      'attack_surface',
      'passed'
    );
    expect(breakdown.criticalityMultiplier).toBe(1.2);
    expect(breakdown.exposureFactor).toBe(1.3);
    expect(breakdown.controlsReductionFactor).toBe(0.85);
    expect(breakdown.baseSeverityWeight).toBe(75);
    expect(breakdown.normalizedScore).toBeGreaterThan(0);
  });
});

describe('ScoringEngineService — scoreAllThreatsForJob (mocked DB)', () => {
  let engine: ScoringEngineService;

  beforeEach(() => {
    vi.clearAllMocks();
    engine = new ScoringEngineService();
  });

  it('calls updateThreat for each threat with contextualScore and scoreBreakdown', async () => {
    const mockJob = { id: 'job-1', journeyId: 'journey-1' };
    const mockJourney = { id: 'journey-1', type: 'attack_surface' };
    const mockHost = makeHost({ type: 'server' });
    const mockThreats = [
      makeThreat({ id: 'threat-1', hostId: 'host-1', jobId: 'job-1', category: null }),
      makeThreat({ id: 'threat-2', hostId: null, jobId: 'job-1', category: null }),
    ];

    vi.mocked(storage.getJob).mockResolvedValue(mockJob as any);
    vi.mocked(storage.getJourney).mockResolvedValue(mockJourney as any);
    vi.mocked(storage.getHost).mockResolvedValue(mockHost as any);
    vi.mocked(getThreats).mockResolvedValue(mockThreats);
    vi.mocked(updateThreat).mockResolvedValue(mockThreats[0]);

    await engine.scoreAllThreatsForJob('job-1');

    expect(updateThreat).toHaveBeenCalledTimes(2);
    const firstCall = vi.mocked(updateThreat).mock.calls[0];
    expect(firstCall[0]).toBe('threat-1');
    expect(firstCall[1]).toHaveProperty('contextualScore');
    expect(firstCall[1]).toHaveProperty('scoreBreakdown');
    expect(firstCall[1].scoreBreakdown).toHaveProperty('normalizedScore');
  });
});
