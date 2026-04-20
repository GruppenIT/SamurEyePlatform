import { describe, it, expect } from 'vitest';
import { getOwaspBadgeInfo } from './owaspBadge';

describe('getOwaspBadgeInfo', () => {
  it('returns {codigo, titulo} for a known key (api1_bola_2023)', () => {
    const result = getOwaspBadgeInfo('api1_bola_2023');
    expect(result).not.toBeNull();
    expect(result!.codigo).toBe('API1:2023');
    expect(result!.titulo).toBe('Quebra de Autorização em Nível de Objeto');
  });

  it('returns null for an unknown key', () => {
    const result = getOwaspBadgeInfo('unknown_key');
    expect(result).toBeNull();
  });

  it('returns null for null input', () => {
    const result = getOwaspBadgeInfo(null);
    expect(result).toBeNull();
  });

  it('returns null for undefined input', () => {
    const result = getOwaspBadgeInfo(undefined);
    expect(result).toBeNull();
  });

  it('returns correct info for api4_rate_limit_2023', () => {
    const result = getOwaspBadgeInfo('api4_rate_limit_2023');
    expect(result).not.toBeNull();
    expect(result!.codigo).toBe('API4:2023');
    expect(result!.titulo).toBe('Consumo Irrestrito de Recursos');
  });
});
