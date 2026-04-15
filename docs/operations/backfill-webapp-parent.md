# Backfill — Web Application parentAssetId

Populates `assets.parent_asset_id` for existing `web_application` assets by matching the URL's hostname to a `host`-type asset.

## Prerequisites
- Schema column `assets.parent_asset_id` already applied (`npm run db:push` after feat/webapp-journey-revisions merge).
- Idempotent; re-runs are safe (only touches rows where parent is NULL).

## Usage

Dry run:
```
cd /opt/samureye
npx tsx --env-file=.env server/scripts/backfillWebAppParent.ts --dry-run
```

Review output. Live run (removes the flag):
```
npx tsx --env-file=.env server/scripts/backfillWebAppParent.ts
```

## Rollback

```sql
UPDATE assets
SET parent_asset_id = NULL
WHERE type = 'web_application';
```

## Limitations
- Only links when `host` asset's `value` matches the URL's hostname exactly (case-sensitive, no DNS resolution, no IP-alias matching).
- Web apps whose hostname has no corresponding host asset remain orphan (`parent_asset_id = NULL`). They continue to work — just not grouped in the tree view.
- Future Attack Surface runs will create the missing host→webapp links automatically for newly discovered pairs.
