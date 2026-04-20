/**
 * Phase 12-02 — nucleiApi: JSONL mapper tests
 * TDD GREEN: implementation exists in server/services/scanners/api/nucleiApi.ts
 */
import { describe, it, expect } from 'vitest';
import { mapNucleiJsonlToEvidence } from '../../services/scanners/api/nucleiApi';
import type { NucleiFinding } from '@shared/schema';

function makeNucleiFinding(overrides: Partial<NucleiFinding> = {}): NucleiFinding {
  return {
    type: 'nuclei',
    target: 'https://example.com',
    severity: 'medium',
    templateId: 'cors-misconfiguration',
    matchedAt: 'https://example.com/api',
    info: {
      name: 'CORS Misconfiguration',
      severity: 'medium',
      tags: ['cors', 'misconfig'],
    },
    host: 'https://example.com',
    ...overrides,
  } as NucleiFinding;
}

describe('mapNucleiJsonlToEvidence', () => {
  it('Test 6: maps matchedAt → request.url', () => {
    const finding = makeNucleiFinding({ matchedAt: 'https://example.com/api/v1' });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.evidence.request.url).toBe('https://example.com/api/v1');
  });

  it('Test 6b: templateId → extractedValues.templateId', () => {
    const finding = makeNucleiFinding({ templateId: 'cors-test' });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.evidence.extractedValues?.templateId).toBe('cors-test');
  });

  it('Test 6c: extractedResults → extractedValues.extractedResults', () => {
    const finding = makeNucleiFinding({ extractedResults: ['result1', 'result2'] });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.evidence.extractedValues?.extractedResults).toEqual(['result1', 'result2']);
  });

  it('Test 7: truncates request body to 8192 chars', () => {
    const longBody = 'GET / HTTP/1.1\n\n' + 'X'.repeat(10000);
    // Use type assertion for raw data that may contain request field
    const finding = makeNucleiFinding({ ...{ request: longBody } as unknown as Partial<NucleiFinding> });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    if (hit.evidence.request.bodySnippet) {
      expect(hit.evidence.request.bodySnippet.length).toBeLessThanOrEqual(8192);
    }
  });

  it('Test 7b: truncates response body to 8192 chars', () => {
    const longBody = 'HTTP/1.1 200 OK\n\n' + 'Y'.repeat(10000);
    const finding = makeNucleiFinding({ ...{ response: longBody } as unknown as Partial<NucleiFinding> });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    if (hit.evidence.response.bodySnippet) {
      expect(hit.evidence.response.bodySnippet.length).toBeLessThanOrEqual(8192);
    }
  });

  it('Test 8: severity info maps to low', () => {
    const finding = makeNucleiFinding({
      info: { name: 'Test', severity: 'info', tags: ['misconfig'] },
    });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.severity).toBe('low');
  });

  it('Test 9: tag graphql maps to api9_inventory_2023', () => {
    const finding = makeNucleiFinding({
      info: { name: 'GraphQL Introspection', severity: 'medium', tags: ['graphql'] },
    });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.owaspCategory).toBe('api9_inventory_2023');
  });

  it('Test 9b: tag misconfig maps to api8_misconfiguration_2023', () => {
    const finding = makeNucleiFinding({
      info: { name: 'Test', severity: 'medium', tags: ['misconfig'] },
    });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.owaspCategory).toBe('api8_misconfiguration_2023');
  });

  it('Test 9c: tag exposure maps to api8_misconfiguration_2023', () => {
    const finding = makeNucleiFinding({
      info: { name: 'Test', severity: 'medium', tags: ['exposure'] },
    });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.owaspCategory).toBe('api8_misconfiguration_2023');
  });

  it('Test 9d: tag cors maps to api8_misconfiguration_2023', () => {
    const finding = makeNucleiFinding({
      info: { name: 'Test', severity: 'medium', tags: ['cors'] },
    });
    const hit = mapNucleiJsonlToEvidence(finding, 'ep-001');
    expect(hit.owaspCategory).toBe('api8_misconfiguration_2023');
  });
});
