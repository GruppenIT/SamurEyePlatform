/**
 * Backfill script: for every web_application asset without parent_asset_id,
 * parse the URL's host and link to the matching host asset by value.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/backfillWebAppParent.ts --dry-run
 *   npx tsx --env-file=.env server/scripts/backfillWebAppParent.ts            # live
 *
 * Safe to re-run (updates only rows where parent_asset_id IS NULL).
 */
import { db } from "../db";
import { assets } from "@shared/schema";
import { and, eq, isNull } from "drizzle-orm";

type HostAsset = { id: string; value: string };

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  console.log(`[backfill-webapp-parent] starting — dry-run=${dryRun}`);

  // Load host assets
  const hostRows = (await db
    .select({ id: assets.id, value: assets.value })
    .from(assets)
    .where(eq(assets.type, "host" as any))) as HostAsset[];

  const hostByValue = new Map<string, string>(); // value → id
  for (const h of hostRows) hostByValue.set(h.value, h.id);

  // Load web apps lacking parent
  const webApps = await db
    .select({ id: assets.id, value: assets.value })
    .from(assets)
    .where(and(eq(assets.type, "web_application" as any), isNull(assets.parentAssetId)));

  console.log(`[backfill-webapp-parent] hosts=${hostRows.length} orphan_webapps=${webApps.length}`);

  let linked = 0;
  let skipped = 0;

  for (const wa of webApps) {
    let hostName: string | null = null;
    try {
      const u = new URL(wa.value);
      hostName = u.hostname;
    } catch {
      console.warn(`  ⚠️  could not parse url: ${wa.value} (asset=${wa.id}) — skipping`);
      skipped += 1;
      continue;
    }

    const parentId = hostByValue.get(hostName);
    if (!parentId) {
      console.log(`  · no matching host for ${hostName} (webapp=${wa.value}) — leaving null`);
      skipped += 1;
      continue;
    }

    if (dryRun) {
      console.log(`  DRY-RUN: would link ${wa.value} → host:${hostName} (parent=${parentId})`);
      linked += 1;
      continue;
    }

    await db
      .update(assets)
      .set({ parentAssetId: parentId })
      .where(eq(assets.id, wa.id));
    console.log(`  ✅ linked ${wa.value} → host:${hostName}`);
    linked += 1;
  }

  console.log(`[backfill-webapp-parent] DONE linked=${linked} skipped=${skipped} mode=${dryRun ? "dry-run" : "live"}`);
  process.exit(0);
}

main().catch((err) => {
  console.error("[backfill-webapp-parent] fatal", err);
  process.exit(1);
});
