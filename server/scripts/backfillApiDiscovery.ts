/**
 * Backfill script (HIER-04): probes existing web_application assets for API
 * indicators and auto-promotes detected ones into the `apis` table.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts --dry-run
 *   npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts            # live
 *
 * Safe to re-run: only processes web_apps that have zero `apis` rows (NOT EXISTS).
 * All probes are GET-only with a 5s timeout and a concurrency cap of 10.
 * No credentials are used — Phase 10 introduces the credential store.
 */
import { db } from "../db";
import { apis, assets } from "@shared/schema";
import { and, eq, sql } from "drizzle-orm";

const SPEC_PATHS = [
  '/openapi.json',
  '/swagger.json',
  '/v2/api-docs',
  '/v3/api-docs',
  '/api-docs',
  '/swagger-ui.html',
  '/graphql',
];
const PROBE_TIMEOUT_MS = 5000;
const CONCURRENCY = 10;
const SYSTEM_USER_ID = 'system';

type ApiType = 'rest' | 'graphql' | 'soap';
type Detection = { apiType: ApiType; specUrl?: string };

export async function probeWebApp(baseUrl: string): Promise<Detection | null> {
  // 1. Spec paths
  for (const p of SPEC_PATHS) {
    let url: string;
    try {
      url = new URL(p, baseUrl).toString();
    } catch {
      continue;
    }
    try {
      const res = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
        redirect: 'follow',
      });
      if (!res.ok) continue;
      const ct = (res.headers.get('content-type') ?? '').toLowerCase();
      if (p === '/graphql') return { apiType: 'graphql', specUrl: url };
      if (ct.includes('application/json')) return { apiType: 'rest', specUrl: url };
    } catch {
      // timeout, DNS, TLS, etc. — continue to next probe
    }
  }

  // 2. /api root
  try {
    const apiRoot = new URL('/api', baseUrl).toString();
    const res = await fetch(apiRoot, {
      method: 'GET',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      redirect: 'follow',
    });
    if (res.ok && (res.headers.get('content-type') ?? '').toLowerCase().includes('application/json')) {
      return { apiType: 'rest' };
    }
  } catch { /* noop */ }

  // 3. Root URL JSON
  try {
    const res = await fetch(baseUrl, {
      method: 'GET',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      redirect: 'follow',
    });
    if (res.ok && (res.headers.get('content-type') ?? '').toLowerCase().includes('application/json')) {
      return { apiType: 'rest' };
    }
  } catch { /* noop */ }

  return null;
}

/**
 * Concurrency-limited map. Processes items in sequential chunks of `limit` each;
 * within a chunk, fn runs in parallel via Promise.all. No external dependency.
 */
export async function batchWithLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  for (let i = 0; i < items.length; i += limit) {
    const chunk = items.slice(i, i + limit);
    const chunkResults = await Promise.all(chunk.map(fn));
    results.push(...chunkResults);
  }
  return results;
}

export async function main(): Promise<void> {
  const dryRun = process.argv.includes('--dry-run');
  console.log(`[backfill-api-discovery] starting — dry-run=${dryRun}`);

  // Load web_application assets that have ZERO api children (NOT EXISTS correlation).
  // Using raw SQL in the correlated subquery — assets.id must be interpolated as the
  // column, not a string (Pitfall 6 — use the drizzle identifier directly).
  const candidates = await db
    .select({ id: assets.id, value: assets.value })
    .from(assets)
    .where(
      and(
        eq(assets.type, 'web_application' as any),
        sql`NOT EXISTS (SELECT 1 FROM apis WHERE apis.parent_asset_id = ${assets.id})`,
      ),
    );

  console.log(`[backfill-api-discovery] candidates=${candidates.length}`);

  let promoted = 0;
  let skipped = 0;

  await batchWithLimit(candidates, CONCURRENCY, async (wa) => {
    console.log(`  · probing ${wa.value} (asset=${wa.id})`);
    const detection = await probeWebApp(wa.value);
    if (!detection) {
      console.log(`  ✗ no api indicator for ${wa.value}`);
      skipped += 1;
      return;
    }

    if (dryRun) {
      console.log(
        `  DRY-RUN: would promote ${wa.value} → apiType=${detection.apiType}` +
          (detection.specUrl ? ` specUrl=${detection.specUrl}` : ''),
      );
      promoted += 1;
      return;
    }

    try {
      const [created] = await db
        .insert(apis)
        .values({
          parentAssetId: wa.id,
          baseUrl: wa.value,
          apiType: detection.apiType,
          specUrl: detection.specUrl ?? null,
          createdBy: SYSTEM_USER_ID,
        })
        .onConflictDoNothing({ target: [apis.parentAssetId, apis.baseUrl] })
        .returning();

      if (created) {
        console.log(
          `  ✅ promoted ${wa.value} → apiType=${detection.apiType}` +
            (detection.specUrl ? ` specUrl=${detection.specUrl}` : ''),
        );
        promoted += 1;
      } else {
        console.log(`  · already exists for ${wa.value} — skipping`);
        skipped += 1;
      }
    } catch (err) {
      console.error(`  ⚠️  failed to insert api for ${wa.value}:`, err);
      skipped += 1;
    }
  });

  console.log(
    `[backfill-api-discovery] DONE promoted=${promoted} skipped=${skipped} mode=${
      dryRun ? 'dry-run' : 'live'
    }`,
  );
  process.exit(0);
}

// Only run when invoked directly via tsx. In tests, importers use the named exports.
// import.meta.url comparison handles both Node CLI and tsx runners.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error('[backfill-api-discovery] fatal', err);
    process.exit(1);
  });
}
