/**
 * EDR parser tests — covers PARS-09, PARS-10
 *
 * Validates that:
 *   - EdrFindingSchema accepts correctly shaped objects with timeline arrays
 *   - EdrFindingSchema rejects invalid objects
 *   - EDR fixtures parse correctly and have correct timeline event sequences
 *   - detection-success has detected: true, detection-failure has detected: false
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { EdrFindingSchema, EdrTimelineEventSchema, type EdrFinding } from '@shared/schema';

const fixturesDir = join(__dirname, 'fixtures/edr');

function loadFixture(name: string): any {
  const content = readFileSync(join(fixturesDir, name), 'utf-8');
  return JSON.parse(content);
}

// ──────────────────────────────────────────────────────────────────────────
// EdrTimelineEventSchema validation
// ──────────────────────────────────────────────────────────────────────────

describe('EdrTimelineEventSchema', () => {
  it('accepts all 6 valid action types', () => {
    const actions = ['deploy_attempt', 'deploy_success', 'detected', 'not_detected', 'timeout', 'cleanup'] as const;
    for (const action of actions) {
      const result = EdrTimelineEventSchema.safeParse({
        timestamp: '2024-03-16T10:00:00Z',
        action,
        detail: `Testing ${action}`,
      });
      expect(result.success).toBe(true);
    }
  });

  it('rejects invalid action type', () => {
    const result = EdrTimelineEventSchema.safeParse({
      timestamp: '2024-03-16T10:00:00Z',
      action: 'invalid_action',
      detail: 'test',
    });
    expect(result.success).toBe(false);
  });

  it('accepts optional share field', () => {
    const result = EdrTimelineEventSchema.safeParse({
      timestamp: '2024-03-16T10:00:00Z',
      action: 'deploy_attempt',
      detail: 'Testing with share',
      share: '\\\\host\\C$',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.share).toBe('\\\\host\\C$');
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────
// EdrFindingSchema validation (PARS-10)
// ──────────────────────────────────────────────────────────────────────────

describe('EdrFindingSchema', () => {
  it('accepts a valid EdrFinding with timeline', () => {
    const valid = {
      type: 'edr_test',
      target: 'host01.corp.com',
      severity: 'low',
      hostname: 'host01.corp.com',
      eicarRemoved: true,
      detected: true,
      deploymentMethod: 'smb',
      testDuration: 30,
      timeline: [
        { timestamp: '2024-03-16T10:00:00Z', action: 'deploy_attempt', detail: 'Attempting' },
        { timestamp: '2024-03-16T10:00:02Z', action: 'deploy_success', detail: 'Deployed' },
        { timestamp: '2024-03-16T10:00:32Z', action: 'detected', detail: 'Removed by EDR' },
      ],
    };
    const result = EdrFindingSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('accepts EdrFinding with null eicarRemoved and null detected (timeout/error case)', () => {
    const valid = {
      type: 'edr_test',
      target: 'host01.corp.com',
      severity: 'medium',
      hostname: 'host01.corp.com',
      eicarRemoved: null,
      detected: null,
      deploymentMethod: 'smb',
      testDuration: 30,
      error: 'timeout',
      timeline: [
        { timestamp: '2024-03-16T10:00:00Z', action: 'deploy_attempt', detail: 'Attempting' },
        { timestamp: '2024-03-16T10:00:30Z', action: 'timeout', detail: 'Timed out' },
      ],
    };
    const result = EdrFindingSchema.safeParse(valid);
    expect(result.success).toBe(true);
  });

  it('rejects missing timeline field', () => {
    const invalid = {
      type: 'edr_test',
      target: 'host01.corp.com',
      severity: 'low',
      hostname: 'host01.corp.com',
      eicarRemoved: true,
      detected: true,
      deploymentMethod: 'smb',
      testDuration: 30,
      // timeline missing
    };
    const result = EdrFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('rejects wrong type literal', () => {
    const invalid = {
      type: 'edr_scan', // wrong — must be 'edr_test'
      target: 'host01.corp.com',
      severity: 'low',
      hostname: 'host01.corp.com',
      eicarRemoved: true,
      detected: true,
      deploymentMethod: 'smb',
      testDuration: 30,
      timeline: [],
    };
    const result = EdrFindingSchema.safeParse(invalid);
    expect(result.success).toBe(false);
  });

  it('strips unknown fields via .strip()', () => {
    const withExtra = {
      type: 'edr_test',
      target: 'host01.corp.com',
      severity: 'low',
      hostname: 'host01.corp.com',
      eicarRemoved: true,
      detected: true,
      deploymentMethod: 'smb',
      testDuration: 30,
      timeline: [],
      unknownField: 'should be stripped',
    };
    const result = EdrFindingSchema.safeParse(withExtra);
    expect(result.success).toBe(true);
    if (result.success) {
      expect((result.data as Record<string, unknown>).unknownField).toBeUndefined();
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────
// Fixture-based tests (PARS-09)
// ──────────────────────────────────────────────────────────────────────────

describe('EDR fixture parsing', () => {
  it('detection-success: validates and has detected: true with correct timeline', () => {
    const raw = loadFixture('detection-success.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      const finding = result.data;
      expect(finding.detected).toBe(true);
      expect(finding.eicarRemoved).toBe(true);
      expect(finding.timeline).toBeDefined();
      expect(finding.timeline.length).toBeGreaterThanOrEqual(3);
      // Verify timeline sequence: deploy_attempt → deploy_success → detected
      const actions = finding.timeline.map(e => e.action);
      expect(actions[0]).toBe('deploy_attempt');
      expect(actions[1]).toBe('deploy_success');
      expect(actions).toContain('detected');
    }
  });

  it('detection-failure: validates and has detected: false with cleanup event', () => {
    const raw = loadFixture('detection-failure.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      const finding = result.data;
      expect(finding.detected).toBe(false);
      expect(finding.eicarRemoved).toBe(false);
      expect(finding.timeline).toBeDefined();
      // Verify timeline has not_detected and cleanup
      const actions = finding.timeline.map(e => e.action);
      expect(actions).toContain('not_detected');
      expect(actions).toContain('cleanup');
    }
  });

  it('timeout-error: validates with null detected and timeout event', () => {
    const raw = loadFixture('timeout-error.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      const finding = result.data;
      expect(finding.detected).toBeNull();
      expect(finding.eicarRemoved).toBeNull();
      expect(finding.error).toBe('timeout');
      expect(finding.timeline).toBeDefined();
      const actions = finding.timeline.map(e => e.action);
      expect(actions).toContain('timeout');
    }
  });

  it('snapshot: detection-success fixture', () => {
    const raw = loadFixture('detection-success.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toMatchSnapshot();
    }
  });

  it('snapshot: detection-failure fixture', () => {
    const raw = loadFixture('detection-failure.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toMatchSnapshot();
    }
  });

  it('snapshot: timeout-error fixture', () => {
    const raw = loadFixture('timeout-error.json');
    const result = EdrFindingSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toMatchSnapshot();
    }
  });
});
