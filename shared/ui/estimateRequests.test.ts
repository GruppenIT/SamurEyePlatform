import { describe, it, expect } from 'vitest';
import { estimateRequests, type StageConfig } from './estimateRequests';

const allFalseConfig: StageConfig = {
  specFirst: false,
  crawler: false,
  kiterunner: false,
  misconfigs: false,
  auth: false,
  bola: false,
  bfla: false,
  bopla: false,
  rateLimitTest: false,
  ssrf: false,
};

describe('estimateRequests', () => {
  it('returns endpointCount * activeStages * 2 (50 endpoints, 5 active stages = 500)', () => {
    const config: StageConfig = {
      specFirst: true,
      crawler: true,
      kiterunner: false,
      misconfigs: true,
      auth: true,
      bola: false,
      bfla: false,
      bopla: false,
      rateLimitTest: true,
      ssrf: false,
    };
    expect(estimateRequests(50, config)).toBe(500);
  });

  it('returns 0 when endpointCount is 0', () => {
    const config: StageConfig = { ...allFalseConfig, specFirst: true, crawler: true };
    expect(estimateRequests(0, config)).toBe(0);
  });

  it('returns 0 when all stages are false', () => {
    expect(estimateRequests(10, allFalseConfig)).toBe(0);
  });

  it('returns endpointCount * 20 when all 10 stages are active', () => {
    const allTrueConfig: StageConfig = {
      specFirst: true,
      crawler: true,
      kiterunner: true,
      misconfigs: true,
      auth: true,
      bola: true,
      bfla: true,
      bopla: true,
      rateLimitTest: true,
      ssrf: true,
    };
    expect(estimateRequests(5, allTrueConfig)).toBe(100);
  });
});
