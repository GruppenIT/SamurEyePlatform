# Run API Discovery (Phase 11)

Manual API discovery runner. Use for operator debug, dry-run smoke tests before Phase 15 wires the full journey, and troubleshooting of spec/crawler/enrichment issues.

## Prerequisites

1. **API registered**: Create an API row via `POST /api/v1/apis` (Phase 9 HIER-03). Note the returned `id`.
2. **Binaries installed**: `install.sh` with Phase 8 binaries (katana, httpx, kiterunner, arjun). Run `./scripts/install/install-binaries.sh` if missing.
3. **Wordlists**: `/opt/samureye/wordlists/routes-large.kite` + `/opt/samureye/wordlists/arjun-extended-pt-en.txt` (Phase 8 vendoring).
4. **(Optional) Credentials**: For authenticated targets, create API credentials via `POST /api/v1/api-credentials` (Phase 10 CRED-01/05) and verify URL patterns match the base URL.

## Usage

### Default (spec + crawler + httpx)

```bash
npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid>
```

### Disable crawler, enable Kiterunner brute-force

```bash
npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid> --no-crawler --kiterunner
```

### Arjun parameter discovery on specific GET endpoints

```bash
npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid> \
  --arjun-endpoint=<endpoint-uuid-1> \
  --arjun-endpoint=<endpoint-uuid-2>
```

### Dry-run (spec + httpx only — useful for non-invasive validation)

```bash
npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid> --dry-run
```

### Force specific credential (overrides URL-pattern resolution)

```bash
npx tsx --env-file=.env server/scripts/runApiDiscovery.ts --api=<uuid> --credential=<cred-uuid>
```

### All flags

| Flag | Default | Effect |
|------|---------|--------|
| `--api=<uuid>` | (required) | Target API row ID |
| `--no-spec` | spec on | Skip spec-first probing |
| `--no-crawler` | crawler on | Skip Katana crawling |
| `--kiterunner` | off | Enable opt-in brute-force |
| `--no-httpx` | httpx on | Skip httpx enrichment |
| `--arjun-endpoint=<eid>` | — | Run Arjun on endpoint ID (repeatable) |
| `--credential=<cid>` | resolve by URL pattern | Force specific credential |
| `--dry-run` | off | Force spec+httpx only (crawler/kiterunner/arjun off) |
| `--katana-depth=<n>` | 3 | Katana crawl depth (1-10) |
| `--katana-headless` | off | Enable headless Chrome crawl |
| `--kiterunner-rate=<n>` | 5 | Kiterunner -x (connections per host) |

## HTTP Route (for automation)

Same functionality via HTTP for CI / UI:

```bash
curl -X POST https://samureye.example.com/api/v1/apis/<apiId>/discover \
  -H "Content-Type: application/json" \
  -H "Cookie: <session>" \
  -d '{
    "stages": { "spec": true, "crawler": true, "kiterunner": false, "httpx": true, "arjun": false },
    "dryRun": false
  }'
```

Returns `202 Accepted` with `{ jobId, result: DiscoveryResult }`.

**RBAC**: Requires authenticated session with role `operator` or `global_administrator`.

**Error codes**:
- `400`: Body fails Zod validation (`discoverApiOptsSchema`) — includes `details` array with issues
- `404`: API with given `:id` not found
- `500`: Internal error during discovery execution

## Output Interpretation

`DiscoveryResult` fields:

- `stagesRun`: ordered list of stages that produced output (`spec`, `crawler`, `kiterunner`, `httpx`, `arjun`)
- `stagesSkipped`: `[{ stage, reason }]` — includes disabled toggles AND missing binaries
- `endpointsDiscovered`: new rows inserted into `api_endpoints`
- `endpointsUpdated`: existing rows updated via dedupe merge (append `discoverySources`, update enrichment fields)
- `endpointsStale`: endpoint IDs present in DB but not seen in this run (not deleted; logged only)
- `specFetched`: present only when spec stage succeeded; `driftDetected=true` when spec hash changed vs previous run (DISC-06)
- `cancelled`: true when AbortSignal fired mid-run (Phase 15 only)
- `durationMs`: total wall-clock time

## Troubleshooting

### "katana binary not available" (or httpx/kiterunner/arjun)

Check `/opt/samureye/bin/{katana,httpx,kiterunner}` (or `kr`) exist and are executable.
For Arjun: `/opt/samureye/venv-security/bin/arjun`.
Run `scripts/install/install-binaries.sh` to install from pinned `binaries.json`.

### "spec drift detected" warning in logs

A previous run observed a different spec hash. Phase 11 logs but does NOT create a finding — this is DISC-06 "detection only". Phase 12/13 may consume this signal.

### Arjun stage throws "pertence a apiId diferente"

Endpoint ID passed via `--arjun-endpoint` belongs to a different API. Verify endpoint's `api_id` matches the `--api` argument.

### Endpoint `requires_auth=true` but 401 persists after auth retry

Credential resolution returned an incompatible type (hmac/mtls/api_key_query). httpx second-pass skips these. Check API credential URL pattern.

### Arjun returns empty params

Normal on endpoints without hidden parameters. Arjun uses response-length + body-delta heuristics with chunked binary search — false positives are rare, false negatives are possible on noisy responses.

### `$ref` SSRF defense rejected an external reference

Check `log.warn` for `rejected cross-origin $ref`. This is Pitfall 1 mitigation — the OpenAPI spec at `baseUrl` referenced a schema on a different origin. Verify the spec is not malicious; if legitimate, contact the API vendor to inline the schema.

### Discovery returns 0 endpoints on first run

Check `stagesSkipped` — if all stages skipped due to missing binaries, no endpoints will be discovered. Run `--dry-run` to test spec+httpx only without binary dependencies.

## Related

- Phase 9 `docs/operations/backfill-api-discovery.md` — auto-register APIs from web_application assets
- Phase 10 `server/routes/apiCredentials.ts` — credential CRUD
- Phase 15 (planned) — journey wiring, abort support, rate governor
- Phase 16 (planned) — UI wizard with endpoint selection for Arjun opt-in
