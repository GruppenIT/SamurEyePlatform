# Backfill — API Discovery from web_application assets

Probes existing `web_application` assets for API indicators and auto-promotes detected ones into the `apis` table (HIER-04). Pairs with `backfill-webapp-parent.md`.

## Prerequisites
- Schema Phase 9 applied (`apis`, `api_endpoints`, `api_findings` tables exist). Either ran `npm run db:push` or the appliance booted with `ensureApiTables()` runtime guard active.
- Idempotent: only processes `web_application` assets with zero existing `apis` rows (NOT EXISTS check).
- No credentials are used — only unauthenticated GET requests.

## How to run

Dry run (recommended first pass):
```
cd /opt/samureye
npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts --dry-run
```

Review the output. Live run (removes the flag):
```
npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts
```

## Detection rules

Any of the following promotes a web_application asset into an `apis` row:

1. **Spec paths** (checked in order, first match wins):
   - `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs`, `/api-docs`, `/swagger-ui.html` — requires `application/json` Content-Type → promoted as `apiType=rest`, `specUrl=<absolute URL>`.
   - `/graphql` — any 2xx response → promoted as `apiType=graphql`, `specUrl=<absolute URL>`.
2. **`/api` root** — responds 2xx with `Content-Type: application/json` → promoted as `apiType=rest`, no `specUrl`.
3. **Site root `/`** — responds 2xx with `Content-Type: application/json` → promoted as `apiType=rest`, no `specUrl`.

## Rate limiting and safety

- Per-request timeout: **5 seconds** (wall-clock, redirects included).
- Concurrency cap: **10 simultaneous probes**.
- Only GET requests — never POST/PUT/DELETE.
- No credentials attached; Phase 10 introduces the credential store.
- Uses system user (`created_by = 'system'`) for auto-promoted rows so auditing can distinguish manual vs backfill registrations via log records.

## What it does NOT do

- Does **not** create `api_endpoints` — endpoint discovery is Phase 11 (Katana + spec parsing + httpx + Arjun).
- Does **not** re-probe already-promoted APIs. If an API was manually registered for a web_application, the backfill skips that asset entirely.
- Does **not** mutate or delete existing `apis` rows.

## Rollback

Remove all rows inserted by the backfill (anything with `created_by = 'system'` and no manually-created `description`):

```sql
DELETE FROM apis
WHERE created_by = 'system'
  AND description IS NULL
  AND name IS NULL;
```

Always dry-run first to see what would be deleted:

```sql
SELECT id, parent_asset_id, base_url, api_type, spec_url, created_at
FROM apis
WHERE created_by = 'system'
  AND description IS NULL
  AND name IS NULL;
```

## Limitations

- **False positives acceptable in this phase.** A site serving JSON at `/` that is not an API (e.g. a static `manifest.json` being served through a legacy redirect) will be promoted. The user may delete it manually. Phase 11 discovery will confirm or refute via spec parsing.
- **Slow targets skipped.** Any target that doesn't respond within 5 seconds (including redirects) is skipped. Document this in your post-backfill review.
- **Remote-probe legal posture.** The backfill only probes assets the user has already registered as `web_application` — registration is the implicit consent. For external pentesting scenarios, use the Phase 15 journey flow with explicit authorization acknowledgment (JRNY-02).

## Live probe smoke-test (manual verification — HIER-04 UAT)

Per `09-VALIDATION.md`, the one manual-only check is confirming the backfill promotes a **real** remote web_application exposing `/openapi.json`. Point the script at a staging/lab target and verify the row appears with `spec_url` populated:

```
npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts --dry-run
# then
npx tsx --env-file=.env server/scripts/backfillApiDiscovery.ts
# then
psql "$DATABASE_URL" -c "SELECT id, parent_asset_id, base_url, api_type, spec_url FROM apis WHERE created_by = 'system' ORDER BY created_at DESC LIMIT 5;"
```
