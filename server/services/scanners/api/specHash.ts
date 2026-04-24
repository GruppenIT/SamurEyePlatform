// Phase 11 DISC-06 — canonical spec hashing for drift detection.
// Recursive key-sort avoids the shallow-sort false-drift pitfall documented in
// RESEARCH.md §"Pitfall 5: specHash false drift from key order".
import crypto from 'crypto';

/**
 * Deep canonicalization: sorts object keys recursively; preserves array order.
 * Returns a NEW value — input is not mutated.
 */
export function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj).sort().reduce<Record<string, unknown>>((acc, k) => {
      acc[k] = canonicalize(obj[k]);
      return acc;
    }, {});
  }
  return value;
}

/**
 * SHA-256 of the canonicalized JSON form. 64-char lowercase hex.
 * Used to populate apis.spec_hash (DISC-06) and detect drift across runs.
 */
export function computeCanonicalHash(spec: unknown): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(canonicalize(spec)))
    .digest('hex');
}
