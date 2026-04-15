/**
 * One-shot migration: ensure every web_application asset value carries an explicit port.
 *
 * Before this script, some assets were created with URLs like `http://host` (no port).
 * The new policy emits explicit ports always. This walks every web_application and
 * rewrites the value via normalizeTarget() if it differs.
 *
 * Usage:
 *   npx tsx --env-file=.env server/scripts/normalizeWebAppPorts.ts --dry-run
 *   npx tsx --env-file=.env server/scripts/normalizeWebAppPorts.ts            # live
 *
 * Idempotent. Skips rows whose value is already normalized or can't be parsed.
 * If normalization would collide with an already-existing asset (same type+value),
 * the conflicting row is left alone and logged.
 */
import { db } from "../db";
import { assets } from "@shared/schema";
import { and, eq } from "drizzle-orm";
import { normalizeTarget } from "../services/journeys/urls";

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  console.log(`[normalize-webapp-ports] starting — dry-run=${dryRun}`);

  const webApps = await db
    .select({ id: assets.id, value: assets.value })
    .from(assets)
    .where(eq(assets.type, "web_application" as any));

  console.log(`[normalize-webapp-ports] web_application rows: ${webApps.length}`);

  let changed = 0;
  let unchanged = 0;
  let failed = 0;
  let collisions = 0;

  for (const wa of webApps) {
    const normalized = normalizeTarget(wa.value);
    if (!normalized) {
      console.warn(`  ⚠️  unparseable value: ${wa.value} (id=${wa.id}) — skipping`);
      failed += 1;
      continue;
    }
    if (normalized === wa.value) {
      unchanged += 1;
      continue;
    }

    // Check collision: does another web_application already exist with the normalized value?
    const [collision] = await db
      .select({ id: assets.id })
      .from(assets)
      .where(and(eq(assets.type, "web_application" as any), eq(assets.value, normalized)))
      .limit(1);

    if (collision && collision.id !== wa.id) {
      console.warn(`  ⚠️  collision: ${wa.value} → ${normalized} already exists as ${collision.id} — leaving original untouched`);
      collisions += 1;
      continue;
    }

    if (dryRun) {
      console.log(`  DRY-RUN: ${wa.value} → ${normalized}`);
      changed += 1;
      continue;
    }

    await db.update(assets).set({ value: normalized }).where(eq(assets.id, wa.id));
    console.log(`  ✅ rewrote ${wa.value} → ${normalized}`);
    changed += 1;
  }

  console.log(`[normalize-webapp-ports] DONE changed=${changed} unchanged=${unchanged} failed=${failed} collisions=${collisions} mode=${dryRun ? "dry-run" : "live"}`);
  process.exit(0);
}

main().catch((err) => {
  console.error("[normalize-webapp-ports] fatal", err);
  process.exit(1);
});
