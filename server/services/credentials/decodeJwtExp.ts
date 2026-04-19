// Phase 10 — CRED-01: helper de parse do claim `exp` de um JWT.
// Usado pelo POST /api/v1/api-credentials para popular bearerExpiresAt
// quando o usuário cadastra credencial bearer_jwt.
//
// Falha silenciosa por design (CONTEXT.md): JWT opaco/malformado retorna null,
// não lança — o backend aceita o JWT mesmo assim.

export function decodeJwtExp(jwt: string): Date | null {
  try {
    if (typeof jwt !== 'string' || jwt.length === 0) return null;
    const parts = jwt.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    );
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
      return null;
    }
    return new Date(payload.exp * 1000);
  } catch {
    return null;
  }
}
