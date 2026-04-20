import { describe, it } from 'vitest';
import { promoteHighCriticalFindings, findDuplicateThreat } from '../services/threatPromotion';
import type { PromotionResult } from '../services/threatPromotion';

// Suppress unused import warnings while stubs remain it.todo
void promoteHighCriticalFindings;
void findDuplicateThreat;
void ({} as PromotionResult);

describe('promoteHighCriticalFindings + findDuplicateThreat (FIND-03)', () => {
  // Severity filter
  it.todo('filtra findings: apenas severity ∈ {high, critical} AND status=open AND promotedThreatId IS NULL qualificam para promoção');
  it.todo('skipped counter incrementa para findings com severity=medium/low/info (não qualificam)');

  // Dedupe strategies
  it.todo('findDuplicateThreat — exact match: threat existente com source=api_security + parentAssetId=apiId + threatTitle contém owaspCategory → retorna o threat existente');
  it.todo('findDuplicateThreat — temporal fallback: sem exact match mas threat com source=api_security criado < 60min atrás → retorna o mais recente');
  it.todo('findDuplicateThreat — retorna null quando não há exact nem temporal match (caminho "create new threat")');

  // Atomicity + linking
  it.todo('promotion criando threat nova executa em db.transaction(): rollback se apiFindings.update falha depois de threats.insert → nenhum registro persiste (atomicity)');
  it.todo('quando dup detectado via findDuplicateThreat, apiFindings.promotedThreatId é atualizado com existing.id + linked counter incrementa (sem INSERT em threats)');

  // Resilience
  it.todo('fail-open: db error (simulated via mock throw) NÃO lança — função retorna { promoted:0, linked:0, skipped:N, error: "..." }; finding permanece com promotedThreatId=null');
});
