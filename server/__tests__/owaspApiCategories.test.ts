import { describe, it, expect } from 'vitest';
import { OWASP_API_CATEGORY_LABELS, DISCOVERY_SOURCES } from '@shared/owaspApiCategories';

describe('OWASP_API_CATEGORY_LABELS (FIND-01)', () => {
  const expectedKeys = [
    'api1_bola_2023',
    'api2_broken_auth_2023',
    'api3_bopla_2023',
    'api4_rate_limit_2023',
    'api5_bfla_2023',
    'api6_business_flow_2023',
    'api7_ssrf_2023',
    'api8_misconfiguration_2023',
    'api9_inventory_2023',
    'api10_unsafe_consumption_2023',
  ];

  it('has exactly 10 entries', () => {
    expect(Object.keys(OWASP_API_CATEGORY_LABELS)).toHaveLength(10);
  });

  it('covers every OWASP API Top 10 2023 category', () => {
    for (const key of expectedKeys) {
      expect(OWASP_API_CATEGORY_LABELS).toHaveProperty(key);
    }
  });

  it('every referenciaOwasp points to owasp.org/API-Security/editions/2023/en/', () => {
    for (const key of expectedKeys) {
      const entry = OWASP_API_CATEGORY_LABELS[key as keyof typeof OWASP_API_CATEGORY_LABELS];
      expect(entry.referenciaOwasp.startsWith('https://owasp.org/API-Security/editions/2023/en/'))
        .toBe(true);
    }
  });

  it('every entry has codigo + titulo + tituloIngles non-empty', () => {
    for (const key of expectedKeys) {
      const entry = OWASP_API_CATEGORY_LABELS[key as keyof typeof OWASP_API_CATEGORY_LABELS];
      expect(entry.codigo).toMatch(/^API\d+:2023$/);
      expect(entry.titulo.length).toBeGreaterThan(0);
      expect(entry.tituloIngles.length).toBeGreaterThan(0);
    }
  });
});

describe('DISCOVERY_SOURCES', () => {
  it('has the 4 locked values in order', () => {
    expect(DISCOVERY_SOURCES).toEqual(['spec', 'crawler', 'kiterunner', 'manual']);
  });
});
