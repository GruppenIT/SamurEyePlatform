import { and, eq, gte, like, desc } from 'drizzle-orm';
import { db } from '../db';
import { threats } from '../../shared/schema';
import { OWASP_API_CATEGORY_LABELS } from '../../shared/owaspApiCategories';
import {
  listFindingsForPromotion,
  updateFindingPromotedThreatId,
} from '../storage/apiFindings';

// ============================================================================
// Internal types
// ============================================================================

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
type ThreatRow = typeof threats.$inferSelect;

// ============================================================================
// Public types
// ============================================================================

export interface PromotionResult {
  promoted: number;   // new threats created
  linked: number;     // findings linked to existing threats (dedupe hit)
  skipped: number;    // findings did not qualify (severity/status/already promoted)
  error?: string;     // fail-open: set when DB error short-circuits the batch
}

// ============================================================================
// findDuplicateThreat
// ============================================================================

const TEMPORAL_DUP_WINDOW_MS = 60 * 60 * 1000; // 60 minutes per 14-CONTEXT.md

/**
 * findDuplicateThreat — 2-strategy dedupe (first match wins):
 *   1. Exact: threat with source='api_security' AND category=apiId
 *      AND title LIKE '%{owaspCategory}%'.
 *   2. Temporal fallback: threat with source='api_security' AND
 *      category=apiId AND createdAt > now-60min (most recent).
 *
 * Uses threats.category to store the apiId (hierarchy grouping per 14-CONTEXT.md).
 * Returns matching threat row or null. Consumed by promoteHighCriticalFindings.
 */
export async function findDuplicateThreat(
  apiId: string,
  owaspCategory: string,
): Promise<ThreatRow | null> {
  // Strategy 1: exact match (category=apiId + source + title contains owaspCategory key)
  const exact = await db
    .select()
    .from(threats)
    .where(
      and(
        eq(threats.category, apiId),
        eq(threats.source, 'api_security'),
        like(threats.title, `%${owaspCategory}%`),
      ),
    )
    .orderBy(desc(threats.createdAt))
    .limit(1);
  if (exact.length > 0) {
    return exact[0];
  }

  // Strategy 2: temporal fallback (last 60min, same apiId + source)
  const since = new Date(Date.now() - TEMPORAL_DUP_WINDOW_MS);
  const temporal = await db
    .select()
    .from(threats)
    .where(
      and(
        eq(threats.category, apiId),
        eq(threats.source, 'api_security'),
        gte(threats.createdAt, since),
      ),
    )
    .orderBy(desc(threats.createdAt))
    .limit(1);
  return temporal[0] ?? null;
}

// ============================================================================
// promoteHighCriticalFindings
// ============================================================================

const PROMOTE_SEVERITIES = new Set(['high', 'critical']);

/**
 * promoteHighCriticalFindings — Wave 1 FIND-03 entry point.
 *
 * Fetches a batch of findings by ID, filters for promotion eligibility
 * (high/critical severity + open status + not already promoted), then for each
 * qualifying finding:
 *   - Runs 2-strategy dedupe via findDuplicateThreat.
 *   - If duplicate found: links finding to existing threat (linked++).
 *   - If no duplicate: atomically creates new threat + links finding in one
 *     db.transaction() (promoted++).
 *
 * Fail-open: any DB error is caught, logged, and returned as result.error.
 * Findings persist regardless; dashboard may show fewer threats until retry.
 *
 * Intended to be called fire-and-forget from route handlers:
 *   void promoteHighCriticalFindings(apiId, newFindingIds).catch(console.warn);
 */
export async function promoteHighCriticalFindings(
  apiId: string,
  newFindingIds: string[],
): Promise<PromotionResult> {
  const result: PromotionResult = { promoted: 0, linked: 0, skipped: 0 };

  try {
    if (newFindingIds.length === 0) {
      return result;
    }

    const findings = await listFindingsForPromotion(newFindingIds);

    for (const finding of findings) {
      // Qualification gate
      if (!PROMOTE_SEVERITIES.has(finding.severity)) {
        result.skipped++;
        continue;
      }
      if (finding.status !== 'open') {
        result.skipped++;
        continue;
      }
      if (finding.promotedThreatId) {
        result.skipped++;
        continue;
      }

      // Dedupe check (outside transaction — read-only)
      const dup = await findDuplicateThreat(apiId, finding.owaspCategory);

      if (dup) {
        // Link path: update finding only, no new threat insert
        await updateFindingPromotedThreatId(finding.id, dup.id);
        result.linked++;
        continue;
      }

      // New threat path: atomic insert + link
      await db.transaction(async (tx: Tx) => {
        const categoryMeta = OWASP_API_CATEGORY_LABELS[finding.owaspCategory as keyof typeof OWASP_API_CATEGORY_LABELS];
        const label = categoryMeta?.titulo ?? finding.owaspCategory;
        // Title: "{OWASP Label pt-BR}: {owaspCategory}" — stores category key for dedupe
        // endpointPath is not available on ApiFinding; use apiEndpointId as reference
        const title = `${label}: ${finding.owaspCategory}`;

        // Build correlationKey: ensures idempotent re-runs link to same threat
        const correlationKey = `api_security:${apiId}:${finding.owaspCategory}:${finding.apiEndpointId}`;

        const [inserted] = await tx
          .insert(threats)
          .values({
            title,
            severity: finding.severity,
            source: 'api_security',
            category: apiId,   // store apiId in category for hierarchy grouping
            correlationKey,
            status: 'open',
            // Phase 16 UI-03 depends on owaspCategory being in evidence so the threats table
            // can render OWASP badges client-side without parsing title strings.
            evidence: {
              apiEndpointId: finding.apiEndpointId,
              owaspCategory: finding.owaspCategory,  // consumed by client OwaspBadge component
              findingIds: [finding.id],
            },
          })
          .returning();

        await updateFindingPromotedThreatId(finding.id, inserted.id, tx as unknown as typeof db);
        result.promoted++;
      });
    }

    return result;
  } catch (err) {
    // Fail-open: findings persist; log warning + return result with error field
    // eslint-disable-next-line no-console
    console.warn('[promoteHighCriticalFindings] failed, findings persist without promotion', {
      apiId,
      error: err instanceof Error ? err.message : String(err),
    });
    result.error = err instanceof Error ? err.message : String(err);
    return result;
  }
}
