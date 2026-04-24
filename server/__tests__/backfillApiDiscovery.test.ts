import { describe, it } from 'vitest';

describe('backfillApiDiscovery (HIER-04)', () => {
  describe('probeWebApp()', () => {
    it.todo('returns { apiType: "rest", specUrl } when /openapi.json responds 200 with application/json');
    it.todo('returns { apiType: "graphql", specUrl } when /graphql responds 200');
    it.todo('returns { apiType: "rest" } (no specUrl) when /api responds 2xx with application/json');
    it.todo('returns { apiType: "rest" } (no specUrl) when root / has Content-Type application/json');
    it.todo('returns null when all probes fail or return non-JSON');
    it.todo('respects AbortSignal.timeout(5000) per request');
  });

  describe('batchWithLimit()', () => {
    it.todo('processes items in batches of size CONCURRENCY=10');
    it.todo('settles all promises (no unhandled rejection on probe failure)');
  });

  describe('main() CLI', () => {
    it.todo('--dry-run prints "would promote" lines and does NOT insert into apis');
    it.todo('live run inserts rows via onConflictDoNothing on (parent_asset_id, base_url)');
    it.todo('skips web_apps that already have ≥1 api row (NOT EXISTS subquery)');
    it.todo('sets createdBy to "system" for backfill-created rows');
    it.todo('exits 0 on success, 1 on fatal error');
    it.todo('logs promoted/skipped counts to stdout');
  });
});
