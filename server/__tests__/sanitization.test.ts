import { describe, it } from 'vitest';
import { sanitizeApiFinding, PII_PATTERNS, REDACT_HEADERS, BODY_TRUNCATE_LIMIT } from '../../shared/sanitization';
import type { ApiFindingEvidence } from '../../shared/schema';

// Suppress unused import warnings while stubs remain it.todo
void sanitizeApiFinding;
void PII_PATTERNS;
void REDACT_HEADERS;
void BODY_TRUNCATE_LIMIT;
void ({} as ApiFindingEvidence);

describe('sanitizeApiFinding (FIND-02)', () => {
  // Header redaction
  it.todo('remove headers sensíveis case-insensitive de evidence.request.headers (Authorization, X-API-Key, X-Auth-Token, Cookie, X-CSRF-Token, Token, API-Key, ApiKey, X-Access-Token)');
  it.todo('preserva headers não-sensíveis de evidence.request.headers (Content-Type, User-Agent, Accept)');

  // Body truncation
  it.todo('trunca evidence.response.bodySnippet para 8192 bytes + append marker [... truncated ...] quando input > 8KB');
  it.todo('mantém evidence.response.bodySnippet unchanged quando input ≤ 8KB');

  // PII masking — 4 patterns
  it.todo('mascara CPF formatado (###.###.###-##) para ***.***.***-** e CPF sem pontuação (11 dígitos) para 11 asteriscos');
  it.todo('mascara CNPJ formatado (##.###.###/####-##) para **.***.***/****-** em bodySnippet + extractedValues');
  it.todo('mascara email (user@domain.com → ***@domain.com) preservando o domínio para context investigativo');
  it.todo('mascara credit card (PAN) preservando last-4 dígitos (e.g., 4532-1234-5678-9090 → ****-****-****-9090)');

  // Purity + resilience
  it.todo('é função pura — não muta o input evidence (verifica via deep equal do objeto original antes/depois)');
  it.todo('fail-open — em erro de regex (input malformado) retorna evidence original sem lançar exception (catch + log warning)');
});
