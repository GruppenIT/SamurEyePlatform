# Phase 13: Security Testing — Active - Research

**Researched:** 2026-04-20
**Domain:** Stateful OWASP API Top 10 security testing — TypeScript in-house scanners (BOLA/BFLA/BOPLA/RateLimit) + Nuclei+interactsh (SSRF)
**Confidence:** HIGH — all design decisions resolved in CONTEXT.md; existing Phase 12 code is a confirmed template; only Nuclei interactsh flag syntax required external cross-check (verified against ProjectDiscovery docs referenced in CONTEXT.md)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**BOLA (TEST-03 / API1)**
- Cred pairing: all creds for API via `listApiCredentials({ apiId })` (or new `listApiCredentialsForApi`). Cap `maxCredentials=4` → max 6 unique pairs. Ordered pairs `(A,B)` only — no mirrored `(B,A)`.
- Scope: `method='GET'` with `requiresAuth=true` only.
- Object ID harvest: GET on list-like endpoints (path has no `{id}` / ends in plural or `/list`), extract up to 3 IDs from JSON fields `id|uuid|pk`.
- Finding criterion: status < 400 AND body.length > 0 AND body does NOT contain `"forbidden"/"unauthorized"/"permission denied"` (case-insensitive). Severity `high`.
- Evidence: `{ credentialAId, credentialBId, objectId, endpointPath }`. Evidence.request = cred B request.
- Request budget: 600 max per API. Rate cap 10 req/s.

**BFLA (TEST-04 / API5)**
- Low-priv identification (OR-logic): highest `priority` int, OR description contains `readonly/read-only/viewer/limited`, OR skip if only 1 cred.
- Admin endpoint heuristic: regex `/(admin|manage|management|system|internal|sudo|superuser|root|console)(\b|\/|$)/i`.
- Method-based testing: default disabled — only GET on admin-path by default; PUT/PATCH/DELETE requires `opts.destructiveEnabled=true`.
- Finding criterion: status < 400 AND not redirect-to-login. Severity `high` (RBAC contrasting) or `medium` (RBAC absent — all creds same status).
- Evidence: `{ credentialId, priorityLevel, matchedPattern, endpointPath }`.
- Request budget: 100 max per API.

**BOPLA (TEST-05 / API3)**
- Target methods: PUT + PATCH only. Requires `opts.destructiveEnabled=true` (whole stage skips otherwise).
- Payload: GET seed body → inject 1 key per request from `BOPLA_SENSITIVE_KEYS` (10 keys). Then GET again for reflection check.
- Sensitive keys list (locked):
  ```
  is_admin, isAdmin, admin, role, roles, permissions, superuser, owner, verified, email_verified
  ```
- Reflection detection: key-path deep compare (not regex). Finding when PUT/PATCH status < 400 AND subsequent GET contains injected key with reflected value.
- Severity: `critical` for `is_admin/role/superuser`; `high` for others.
- Evidence: `{ injectedKey, originalValue, reflectedValue, endpointPath }`.
- Request budget: `endpointsPutPatch × 20`. Cap 200 per API.

**Rate-Limit (TEST-06 / API4)**
- Opt-in: `opts.stages.rateLimit=false` default. Must explicitly enable.
- Burst: `Promise.all` of N requests in parallel. `burstSize` default 20, max 50.
- Target: only 1 endpoint per API by default (first GET+200, alphabetical). Override via `opts.rateLimit.endpointIds` (up to 5).
- Detection: ALL of: no 429, no `Retry-After`, no `/^x-ratelimit-/i` headers, ≥90% status < 400. Severity `medium`.
- Evidence: `{ burstSize, successCount, throttledCount, hasRetryAfter, hasXRateLimitHeaders, windowMs, endpointPath }`.

**SSRF (TEST-07 / API7)**
- Scope: only params whose value is URL-like (3 heuristics: name regex, type/format match, example URL parse).
- URL-like name regex (locked):
  ```
  /^(url|redirect|redirect_uri|callback|callback_url|webhook|webhook_url|target|dest|destination|endpoint|uri|link|image_url|avatar_url|src|href|next|continue|returnTo|return_to|return)$/i
  ```
- Nuclei config: `-tags ssrf`, NO `-ni` flag (interactsh enabled). Pass `-interactsh-url <URL>` when `INTERACTSH_URL` env present; else default `oast.me`. Rate `-rl 10`, `-timeout 30`, `-retries 0`, `-silent`, `-jsonl`. Plus `-interactions-poll-duration 5s -interactions-wait 10s -interactions-retries-count 3`.
- Run authenticated (via `resolveApiCredential`).
- Finding criterion: Nuclei JSONL reports `interaction=true` OR `extracted-results` contains interactsh callback URL.
- Evidence: `{ paramName, interactsh_interaction_type, interactshUrl: 'prefix***' }`.

**Orchestrator**
- Function `runApiActiveTests(apiId, opts, jobId?): Promise<ActiveTestResult>` in `server/services/journeys/apiActiveTests.ts`.
- Route: `POST /api/v1/apis/:id/test/active` (RBAC `global_administrator` + `operator`).
- CLI: `server/scripts/runApiActiveTests.ts` with flags `--api --no-bola --no-bfla --no-bopla --no-ssrf --rate-limit --destructive --dry-run --credential`.
- Stage order: `bola → bfla → bopla → rate_limit → ssrf`. Each stage independent.
- `preflightNuclei()` only before SSRF stage.
- Cooperative cancellation: check `jobQueue.isJobCancelled(jobId)` between stages and between endpoints in BOLA loop.
- Total timeout per API: 45 minutes.
- Zod schema `apiActiveTestOptsSchema` with `.strict()` on root and `stages` sub-object.

**Findings**
- Dedupe: reuse `upsertApiFindingByKey(endpointId, category, title, data)` from Phase 12 — zero change.
- Titles (deterministic, dedupe-safe):
  - BOLA: `"Acesso não autorizado a objeto via credencial secundária"`
  - BFLA: `"Privilégio administrativo acessível via credencial de baixo privilégio"`
  - BOPLA: `"Campo sensível aceito em PUT/PATCH sem validação ({{key}})"` — key substituted
  - Rate-limit: `"Ausência de rate-limiting em endpoint autenticado"`
  - SSRF: `"SSRF confirmado via interação out-of-band em parâmetro {{paramName}}"` — paramName substituted
- Remediation: extend `shared/apiRemediationTemplates.ts` with 5 new entries (api1/api3/api4/api5/api7). Exact strings defined in CONTEXT.md.
- `riskScore`: NULL (Phase 14 owner).
- Mask-at-source: never store full token/key. 3-char prefix + `***`.

**dryRun / Fixtures**
- Fixtures in `server/__tests__/fixtures/api-active/` (5-6 files):
  - `bola-crossaccess-response.json`
  - `bfla-admin-success.json`
  - `bopla-reflection-before.json` + `bopla-reflection-after.json`
  - `rate-limit-burst-responses.json` (array of 20 responses, all 200, no throttle signals)
  - `ssrf-nuclei-interaction.jsonl` (1 JSONL line with `interaction=true`)
- `dryRun=true`: no HTTP, no Nuclei spawn. Each stage reads its fixture. Findings prefixed `[DRY-RUN]`.

**Nyquist Wave 0: 15 test stubs minimum**
- `shared/schema.ts` `apiActiveTestOptsSchema`: 3 tests (defaults, ceiling caps, destructive gate)
- `bola.ts`: 3 tests (pair generation, ID harvest, cross-access finding)
- `bfla.ts`: 2 tests (low-priv heuristics, admin path regex)
- `bopla.ts`: 2 tests (seed + inject + reflect, destructive gate skip)
- `rateLimit.ts`: 2 tests (burst parallelism, all-3-signals detection)
- `ssrfNuclei.ts`: 2 tests (URL-like param identification, interactsh flag injection)
- `apiActiveTests.ts` orchestrator: 1 test (stage order + cancel + dryRun)

### Claude's Discretion

- Exact internal function names (`harvestObjectIds`, `pairCredentials`, `detectReflection`, `buildBurst`, `identifyUrlParams`, etc.)
- Whether `listApiCredentialsForApi(apiId)` is a new storage method or inline query in BOLA scanner
- Exact internal structure of `ActiveTestResult` (planner may add fields without breaking)
- Exact shape of fixtures (JSON/JSONL)
- Exact pt-BR error messages in route/CLI
- Import order, file headers (follow CONVENTIONS.md)
- Whether `harvestObjectIds` becomes a shared util or stays inline in `bola.ts`
- Exact shape of path-template parser table (`{id}` vs `:id` vs `<id>`)
- `p-limit` vs `Promise.all` in burst (CONTEXT.md recommends `Promise.all` as sufficient)

### Deferred Ideas (OUT OF SCOPE)

- BOLA with IDs inferred from query param history
- Automatic bidirectional BOLA `(A,B)` + `(B,A)`
- BOPLA with custom operator-supplied keys (`opts.bopla.additionalKeys`)
- Burst ramp-up (5→10→20→50) for threshold detection
- SSRF cloud-metadata payloads beyond official templates
- SSRF DNS rebinding
- Full BFLA matrix (`opts.bfla.fullMatrix`)
- JWT claim forgery in BFLA (alg:none + role claim)
- Race-condition authorization bypass
- Per-stage duration metrics
- Cross-API parallelism within a job
- Auto-retry with backoff on transient failures
- BOLA ↔ BOPLA cross-stage inference
- API6 Business Flow (explicitly out of v2.0)
- API10 Unsafe Consumption (out of v2.0)
- Formal audit trail in `audit_log` table (Phase 15 SAFE-04)
- Custom Nuclei OWASP API templates
- Interactsh self-hosted auto-setup (runbook only)
- BOPLA in POST (create) endpoints

</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-03 | BOLA tests (cross-identity object access) when ≥2 distinct credentials supplied (API1) | BOLA scanner design: `pairCredentials` → `harvestObjectIds` → `testCrossAccess`; `listApiCredentials({apiId})` already exists in `server/storage/apiCredentials.ts` |
| TEST-04 | BFLA tests (admin-level endpoint/method access with low-privilege credential) (API5) | BFLA scanner design: `identifyLowPrivCreds` (3-signal OR) → `matchAdminEndpoint` (path regex) → `testPrivEscalation`; `apiCredentials.priority` and `.description` fields carry-forward from Phase 10 |
| TEST-05 | BOPLA / Mass Assignment tests (injects sensitive property names into PUT/PATCH and inspects reflection) (API3) | BOPLA scanner design: `fetchSeedBody` → `injectSensitiveKey` → `verifyReflection` via deep key-path compare; destructive gate via `opts.destructiveEnabled` |
| TEST-06 | Rate-limit-absence tests via burst N requests — opt-in (API4) | `rateLimit.ts` scanner: `buildBurst` (Promise.all N fetch) → `detectThrottling` (3-signal check); 1 endpoint per API default |
| TEST-07 | SSRF tests via Nuclei + interactsh on URL-accepting params (API7) | `ssrfNuclei.ts` scanner: `identifyUrlParams` (3-heuristic OR) → `runSsrfNuclei` adapting Phase 12 `nucleiApi.ts` but without `-ni`, adding `-interactsh-url` + `-interactions-*` flags; `preflightNuclei()` reused |

</phase_requirements>

---

## Summary

Phase 13 delivers 5 stateful security scanners that require multi-credential state and cross-request context — vectors Nuclei cannot express. The architecture is a direct extension of Phase 12 ("passive → active") following the same three-surface pattern: a pure function orchestrator, an HTTP route, and a CLI script.

Four of the five scanners (`bola.ts`, `bfla.ts`, `bopla.ts`, `rateLimit.ts`) are TypeScript-native using `fetch()` and `crypto` — no external binary. The fifth (`ssrfNuclei.ts`) adapts the Phase 12 `nucleiApi.ts` wrapper with two changes: `ssrf` tag instead of `misconfig,exposure,graphql,cors`, and removal of the `-ni` flag to enable interactsh OOB interaction tracking.

The primary research concern — Nuclei interactsh flag syntax — is resolved: `-interactsh-url <URL>` overrides the default `oast.me` server; `-interactions-poll-duration`, `-interactions-wait`, and `-interactions-retries-count` control OOB polling. The existing `listApiCredentials({ apiId })` function in `server/storage/apiCredentials.ts` provides all credentials for an API and is the existing method BOLA will use, making a new `listApiCredentialsForApi` helper optional (inline Drizzle query is equally viable and saves an IStorage extension).

**Primary recommendation:** Replicate Phase 12 structure 1:1. Add 5 scanner files in `server/services/scanners/api/`, 1 orchestrator in `server/services/journeys/apiActiveTests.ts`, extend `shared/schema.ts` with `apiActiveTestOptsSchema` + `ActiveTestResult`, extend `shared/apiRemediationTemplates.ts`, add 1 route handler in `server/routes/apis.ts`, 1 CLI script, 1 runbook, 5-6 fixtures, and 15 Nyquist test stubs.

---

## Standard Stack

### Core (all carry-forward — zero new dependencies)

| Library / API | Version | Purpose | Source |
|---------------|---------|---------|--------|
| Node.js `fetch` (global) | Node 20+ built-in | HTTP requests for BOLA/BFLA/BOPLA/RateLimit | Phase 12 `authFailure.ts` pattern |
| `node:crypto` | Node 20+ built-in | UUID generation, base64url, mask operations | Phase 12 pattern |
| `nuclei` binary | v1.0 installed (Phase 8) | SSRF testing via `-tags ssrf` + interactsh | Phase 12 `nucleiApi.ts` template |
| `preflightNuclei` | local `server/services/journeys/nucleiPreflight.ts` | Binary check before SSRF stage only | Phase 12 direct reuse |
| `upsertApiFindingByKey` | `server/storage/apiFindings.ts` Phase 12 | Dedupe transactional upsert for all 5 vectors | Zero change — reuse as-is |
| `listApiCredentials` | `server/storage/apiCredentials.ts` Phase 10 | Fetch all creds for BOLA pairing + BFLA ranking | Already exists — `listApiCredentials({ apiId })` |
| `getApiCredentialWithSecret` | `server/storage/apiCredentials.ts` Phase 10 | Decrypt cred secret for header injection | Already exists |
| `resolveApiCredential` | `server/storage/apiCredentials.ts` Phase 10 | Resolve single best cred for SSRF stage | Already exists |
| `processTracker` | `server/services/processTracker.ts` | Register Nuclei child process for SSRF | Phase 12 pattern |
| `jobQueue.isJobCancelled` | `server/services/jobQueue.ts` | Cooperative cancellation in long loops | Phase 12 pattern |
| `encryptionService.decryptCredential` | `server/services/encryption.ts` | Decrypt secret from `secretEncrypted+dekEncrypted` | Phase 12 pattern (via `getApiCredentialWithSecret`) |
| Zod 3.24 | 3.24.2 (package.json) | `apiActiveTestOptsSchema` with `.strict()` + ceilings | Phase 12 pattern |
| Drizzle ORM | 0.39.1 | Query `api_endpoints` with method/requiresAuth filters | Phase 12 pattern |

### No New npm Packages Required

Phase 13 requires zero new `npm install` commands. All functionality is achievable with the existing stack:
- `Promise.all` for rate-limit burst (no `p-limit` needed — burst is intentional saturation)
- Native `fetch` for all in-house TS scanner HTTP calls
- Native `JSON.parse` for deep-merge / seed body parsing
- Native `URL` constructor for example URL parse heuristic

---

## Architecture Patterns

### Recommended Project Structure (additions only)

```
server/services/scanners/api/
├── bola.ts           # TEST-03: pairCredentials + harvestObjectIds + testCrossAccess
├── bfla.ts           # TEST-04: identifyLowPrivCreds + matchAdminEndpoint + testPrivEscalation
├── bopla.ts          # TEST-05: fetchSeedBody + injectSensitiveKey + verifyReflection
├── rateLimit.ts      # TEST-06: buildBurst + detectThrottling
└── ssrfNuclei.ts     # TEST-07: identifyUrlParams + runSsrfNuclei (adapts nucleiApi.ts)

server/services/journeys/
└── apiActiveTests.ts # Orchestrator: stages bola→bfla→bopla→rate_limit→ssrf

server/scripts/
└── runApiActiveTests.ts   # Operator CLI

docs/operations/
└── run-api-active-tests.md   # Runbook pt-BR

server/__tests__/
├── fixtures/api-active/      # 5-6 dryRun fixtures
│   ├── bola-crossaccess-response.json
│   ├── bfla-admin-success.json
│   ├── bopla-reflection-before.json
│   ├── bopla-reflection-after.json
│   ├── rate-limit-burst-responses.json
│   └── ssrf-nuclei-interaction.jsonl
└── apiActive/                # 15 Nyquist test stubs
    ├── schema.test.ts         (3 stubs)
    ├── bola.test.ts           (3 stubs)
    ├── bfla.test.ts           (2 stubs)
    ├── bopla.test.ts          (2 stubs)
    ├── rateLimit.test.ts      (2 stubs)
    ├── ssrfNuclei.test.ts     (2 stubs)
    └── orchestrator.test.ts   (1 stub)

shared/
├── schema.ts                  (extend: apiActiveTestOptsSchema + ActiveTestResult)
└── apiRemediationTemplates.ts (extend: 5 new entries)
```

### Pattern 1: Scanner-per-vector (in-house TS)

**What:** Each scanner is an isolated module with 2-3 pure/async functions and a typed `Hit` interface parallel to `AuthFailureHit` in Phase 12.
**When to use:** BOLA, BFLA, BOPLA, RateLimit — all use native `fetch`, no external binary.
**Example (authFailure.ts as template):**
```typescript
// Source: server/services/scanners/api/authFailure.ts (Phase 12)
export interface AuthFailureHit {
  endpointId: string;
  owaspCategory: 'api2_broken_auth_2023';
  severity: 'high' | 'critical';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}
```

Phase 13 scanners follow the same interface shape, e.g.:
```typescript
// bola.ts — analogous pattern
export interface BolaHit {
  endpointId: string;
  owaspCategory: 'api1_bola_2023';
  severity: 'high';
  title: string;
  description: string;
  remediation: string;
  evidence: ApiFindingEvidence;
}
```

### Pattern 2: Nuclei SSRF wrapper (ssrfNuclei.ts adapts nucleiApi.ts)

**What:** `nucleiApi.ts` is the template. SSRF changes: different tags, no `-ni`, added interactsh flags.
**When to use:** TEST-07 only.

```typescript
// Source: adapted from server/services/scanners/api/nucleiApi.ts (Phase 12)
// Key change: SSRF tags + interactsh flags

export function buildSsrfNucleiArgs(opts: SsrfNucleiOpts): string[] {
  const args = [
    '-tags', 'ssrf',
    '-jsonl',
    '-silent',
    '-retries', '0',
    '-rl', String(opts.rateLimit ?? 10),
    '-timeout', String(opts.timeoutSec ?? 30),  // longer: OOB callback needs time
    '-t', TEMPLATES_DIR,
    '-l', '/dev/stdin',
    // interactsh — note: NO -ni flag here (unlike nucleiApi.ts passive scan)
    '-interactions-poll-duration', '5s',
    '-interactions-wait', '10s',
    '-interactions-retries-count', '3',
  ];
  // Override interactsh server when INTERACTSH_URL env is set (air-gapped)
  const interactshUrl = opts.interactshUrl ?? process.env.INTERACTSH_URL;
  if (interactshUrl) {
    args.push('-interactsh-url', interactshUrl);
  }
  return args;
}
```

**Critical difference from `nucleiApi.ts`:** The Phase 12 `nucleiApi.ts` has no `-ni` flag (confirmed: `-ni` is only in `vulnScanner.ts:130`). The `buildNucleiArgs` function in `nucleiApi.ts` already does NOT add `-ni`. Therefore `ssrfNuclei.ts` inherits the same no-`-ni` behavior automatically — but adds the explicit interactsh polling flags.

### Pattern 3: Path-template substitution for BOLA

**What:** OpenAPI uses `{id}` style (confirmed from CONTEXT.md). Regex `/\{(\w+)\}/g` matches all template segments.
**When to use:** When constructing cross-access URL from a harvested object ID.

```typescript
// Source: CONTEXT.md §Path-template parsing
function substitutePathId(pathTemplate: string, id: string | number): string {
  // OpenAPI {id}, {userId}, {itemId}, etc.
  return pathTemplate.replace(/\{(\w+)\}/g, String(id));
}
// Fallback: if no {param} in path, append ?id=<val>
function buildAccessUrl(baseUrl: string, path: string, id: string | number): string {
  const substituted = substitutePathId(path, id);
  if (substituted === path) {
    // No template param found — append as query param
    const sep = path.includes('?') ? '&' : '?';
    return `${baseUrl}${path}${sep}id=${id}`;
  }
  return `${baseUrl}${substituted}`;
}
```

### Pattern 4: BOPLA deep-merge and reflection detection

**What:** Inject one key at a time into seed body; compare before/after GET with key-path equality.
**When to use:** TEST-05 PUT/PATCH endpoints with destructive gate.

```typescript
// Inject a single key without replacing existing structure
function injectKey(
  seedBody: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const injectedValue = typeof seedBody[key] === 'boolean'
    ? true
    : typeof seedBody[key] === 'string'
      ? 'admin'
      : typeof seedBody[key] === 'object' && Array.isArray(seedBody[key])
        ? ['admin']
        : true; // default for unknown/absent
  return { ...seedBody, [key]: injectedValue };
}

// Reflection: key-path deep compare (not regex) — avoids false positives
function isKeyReflected(
  beforeBody: Record<string, unknown>,
  afterBody: Record<string, unknown>,
  key: string,
): boolean {
  const before = beforeBody[key];
  const after = afterBody[key];
  // Reflected when key appears in after with a different/escalated value
  if (after === undefined) return false;
  if (before === after) return false; // value unchanged — likely already existed
  return true;
}
```

### Pattern 5: Credential injection for in-house TS scanners

**What:** How to inject auth headers from a decrypted credential into a `fetch` call.
**Source:** Phase 12 `authFailure.ts` + Phase 10 `resolveApiCredential` / `getApiCredentialWithSecret`.

```typescript
// Supported auth types for Phase 13 (Phase 10 constraint: hmac/mtls/oauth2 skip with log)
function buildAuthHeaders(
  cred: ApiCredentialWithSecret,
  secret: string,
): Record<string, string> {
  switch (cred.authType) {
    case 'bearer_jwt':
      return { Authorization: `Bearer ${secret}` };
    case 'api_key_header':
      return { [cred.apiKeyHeaderName!]: secret };
    case 'basic': {
      const b64 = Buffer.from(`${cred.basicUsername}:${secret}`).toString('base64');
      return { Authorization: `Basic ${b64}` };
    }
    case 'api_key_query':
      // query param — added at URL level, not header; return empty headers
      return {};
    default:
      // hmac, oauth2, mtls — skip stage with log (Phase 13 constraint)
      throw new Error(`Auth type ${cred.authType} not supported by Phase 13 active scanners`);
  }
}
```

### Pattern 6: Orchestrator structure (direct replica of apiPassiveTests.ts)

**What:** Sequential stages, independent failure, cooperative cancellation, dryRun fixture loading, findingsByCategory/Severity counters, single `persistHit` helper.
**Source:** `server/services/journeys/apiPassiveTests.ts` — read in full above.

Key implementation points confirmed from reading `apiPassiveTests.ts`:
- `finalize()` is an inner closure capturing all mutable state — single exit point for cancel/normal paths.
- `persistHit` helper calls `storage.upsertApiFindingByKey` and updates counters.
- `checkCancel()` returns `boolean` — call between stages and between endpoints in long loops.
- `FIXTURE_DIR` uses `join(process.cwd(), 'server/__tests__/fixtures/api-active')`.
- dryRun path reads fixture file via `readFile`, processes exactly as if real output.

### Anti-Patterns to Avoid

- **Mirroring BOLA pairs `(B,A)` in the same run:** doubles request budget for identical coverage. Use ordered pairs only.
- **Running BOPLA without destructive gate check:** whole stage must skip when `opts.destructiveEnabled !== true`. Gate check is the first line of the stage handler.
- **Using `-ni` in ssrfNuclei.ts:** `-ni` (no-interactsh) defeats the entire SSRF OOB detection strategy. The flag must NOT appear in `buildSsrfNucleiArgs`.
- **Bursting all GET endpoints for rate-limit test:** 50 endpoints × 20 burst = 1000 requests — unintentional DoS. Default: 1 endpoint per API.
- **Storing harvested object IDs in pino logs:** SAFE-06 violation. Log only counts and endpoint IDs.
- **Storing full credential secret in evidence.extractedValues:** mask at source: `secret.slice(0, 3) + '***'`.
- **Adding `-ni` to the passive nucleiApi.ts:** `nucleiApi.ts` must remain unchanged; only `ssrfNuclei.ts` activates interactsh.
- **Creating a new route file for active tests:** handler goes into existing `server/routes/apis.ts` alongside the passive test handler — no new file.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Findings deduplication | Custom ON CONFLICT or set-based merge | `upsertApiFindingByKey` (Phase 12) | Already implements transaction with status-aware reopen logic — ON CONFLICT can't express it |
| Credential resolution | Custom URL-pattern matching | `resolveApiCredential` / `listApiCredentials` (Phase 10) | Pattern matching edge cases (globstar, specificity tie-break) already handled |
| Nuclei process lifecycle | Custom spawn wrapper | Adapt `nucleiApi.ts` spawn pattern (Phase 12) | processTracker registration, SIGTERM graceful, SIGKILL timeout, signal abort — all solved |
| Credential secret decryption | Direct `decryptCredential` call | `getApiCredentialWithSecret(id)` (Phase 10) | Only safe method — prevents accidental logging of `secretEncrypted` raw value |
| JSON body deep-key injection | Replace entire body | `{ ...seedBody, [key]: injectedValue }` spread | Preserves seed types; only adds/overrides one key at a time — required for accurate reflection detection |
| OOB interaction tracking for SSRF | Custom HTTP callback server | Nuclei + interactsh via `-tags ssrf` without `-ni` | ProjectDiscovery's interactsh handles DNS/HTTP/SMTP OOB with polling — weeks of custom infra |
| Auth header construction | Per-request manual header building | `buildAuthHeaders` helper (local, per pattern above) | 4 auth types have subtly different header shapes; centralizing prevents bugs in each scanner |

---

## Critical Unknowns — Resolved

### 1. `listApiCredentialsForApi` — does it exist?

**Status: RESOLVED — not needed as new method.**

`server/storage/apiCredentials.ts` already exports:
```typescript
export async function listApiCredentials(
  filter?: { apiId?: string; authType?: ApiAuthType }
): Promise<ApiCredentialSafe[]>
```
Calling `listApiCredentials({ apiId })` returns all credentials for a given API (including global `apiId=null` credentials that match via URL pattern). BOLA can use this directly. The planner may add a thin `listApiCredentialsForApi(apiId)` wrapper in `apiCredentials.ts` as a named alias for clarity, but it is NOT required to extend `IStorage` — the planner decides.

**Recommendation:** Inline `listApiCredentials({ apiId })` directly in `bola.ts` / orchestrator. No new IStorage method needed.

### 2. Nuclei interactsh flags — confirmed syntax

**Status: RESOLVED (HIGH confidence — CONTEXT.md references ProjectDiscovery official docs).**

```
# Enable interactsh (simply do NOT pass -ni)
nuclei -tags ssrf \
  -interactsh-url https://oast.me \           # optional — Nuclei uses oast.me by default
  -interactions-poll-duration 5s \            # how often to poll the interactsh server
  -interactions-wait 10s \                    # wait time after scan ends for late callbacks
  -interactions-retries-count 3 \             # retry polling on network error
  -rl 10 -timeout 30 -retries 0 -silent -jsonl \
  -l /dev/stdin
```

The Phase 12 `nucleiApi.ts` already does NOT pass `-ni` in `buildNucleiArgs`. `-ni` only appears in `vulnScanner.ts:130` (v1.0 legacy scanner). `ssrfNuclei.ts` inherits the clean baseline from `nucleiApi.ts` and adds the three `-interactions-*` flags.

### 3. Path-template parsing — `{id}` is the only format

**Status: RESOLVED — confirmed from CONTEXT.md and Phase 11 context.**

`api_endpoints.path` values come from OpenAPI spec parsing (`@apidevtools/swagger-parser`) and Katana/Kiterunner crawling. OpenAPI 2.0/3.x uses `{paramName}` format. Katana and Kiterunner output path literals (no template syntax). Express `:param` style does NOT appear in external API paths stored in `api_endpoints`. Regex `/\{(\w+)\}/g` is sufficient.

### 4. JSON body deep-merge for BOPLA injection

**Status: RESOLVED — spread operator approach.**

Use ES object spread: `{ ...seedBody, [key]: injectedValue }` to add a single key without replacing the seed structure. Seed is the JSON-parsed response body from GET. Type inference for injected value: check `typeof seedBody[key]` → if exists, match type; if absent, default to `true` (boolean) for `isAdmin/verified/etc.` or `'admin'` (string) for `role/permissions/etc.`. Key-path deep compare for reflection: compare `beforeBody[key]` vs `afterBody[key]` (not recursive — only top-level keys from BOPLA_SENSITIVE_KEYS list).

### 5. Rate-limit burst — `Promise.all` is sufficient

**Status: RESOLVED — per CONTEXT.md explicit decision.**

`Promise.all(Array.from({ length: burstSize }, () => fetch(url, { headers })))` achieves simultaneous burst. No `p-limit` needed — the purpose IS to saturate. Post-burst: inspect all responses for 429/Retry-After/X-RateLimit-* headers.

### 6. Object ID harvest heuristic

**Status: RESOLVED — from CONTEXT.md.**

```typescript
function harvestObjectIds(body: unknown): Array<string | number> {
  if (typeof body !== 'object' || body === null) return [];
  const ids: Array<string | number> = [];
  function scan(obj: Record<string, unknown>): void {
    for (const [key, val] of Object.entries(obj)) {
      if (/^(id|uuid|pk)$/i.test(key) && (typeof val === 'string' || typeof val === 'number')) {
        ids.push(val);
        if (ids.length >= 3) return;
      }
    }
  }
  if (Array.isArray(body)) {
    for (const item of body) {
      if (typeof item === 'object' && item !== null) scan(item as Record<string, unknown>);
      if (ids.length >= 3) break;
    }
  } else {
    scan(body as Record<string, unknown>);
  }
  return ids.slice(0, 3);
}
```

### 7. URL-like param identification

**Status: RESOLVED — name regex + type/format check + URL constructor parse (from CONTEXT.md).**

```typescript
function isUrlLikeParam(param: { name: string; type?: string; format?: string; example?: string }): boolean {
  const NAME_REGEX = /^(url|redirect|redirect_uri|callback|callback_url|webhook|webhook_url|target|dest|destination|endpoint|uri|link|image_url|avatar_url|src|href|next|continue|returnTo|return_to|return)$/i;
  if (NAME_REGEX.test(param.name)) return true;
  if (param.type === 'url' || param.format === 'uri' || param.format === 'url') return true;
  if (param.example) {
    try { new URL(param.example); return true; } catch { /* not a URL */ }
  }
  return false;
}
```

### 8. `preflightNuclei` return signature

**Status: RESOLVED — confirmed from nucleiApi.ts source.**

```typescript
// server/services/journeys/nucleiPreflight.ts returns:
interface PreflightResult {
  ok: boolean;
  reason?: string;
}
```
Usage pattern from `nucleiApi.ts`:
```typescript
const preflight = await preflightNuclei(log);
if (!preflight.ok) {
  return { findings: [], skipped: { reason: preflight.reason ?? 'nuclei unavailable' } };
}
```
`ssrfNuclei.ts` uses identical pattern.

### 9. `encryptionService.decryptCredential` signature

**Status: RESOLVED — confirmed from apiPassiveTests.ts usage.**

```typescript
// server/services/encryption.ts
encryptionService.decryptCredential(secretEncrypted: string, dekEncrypted: string): string
```
Called after `getApiCredentialWithSecret(id)` returns `ApiCredentialWithSecret` with `secretEncrypted` and `dekEncrypted` fields.

---

## Common Pitfalls

### Pitfall 1: BOLA spending budget on non-list endpoints for harvest

**What goes wrong:** Harvesting IDs from detail-endpoints (path contains `{id}`) returns the object's own ID, not a collection. Cross-access test `(A,B)` where B uses A's own-object-ID is not meaningful BOLA evidence.
**Why it happens:** Forgetting the list-endpoint filter before harvest.
**How to avoid:** Filter harvest candidates to paths that do NOT match `/\{(\w+)\}/g` AND (end in plural noun OR end in `/list`).
**Warning signs:** All harvested IDs are the same value across endpoints.

### Pitfall 2: BFLA false positive from "universal" credential

**What goes wrong:** Low-priv credential identified by `priority` is actually an admin credential that passes all endpoints — BFLA finding fires on non-admin endpoints too.
**Why it happens:** `priority` integer ranking is a heuristic, not a ground truth.
**How to avoid:** Skip condition: if low-priv cred passes non-admin endpoints with same success rate as other creds, log warn and skip BFLA for this cred. This condition is specified in CONTEXT.md.
**Warning signs:** `findingsCount > adminEndpointCount`.

### Pitfall 3: BOPLA mutation leaving persistent state on real target

**What goes wrong:** PUT/PATCH with `is_admin: true` succeeds and reflection is confirmed — but the change is REAL. The test has escalated privileges on the actual user.
**Why it happens:** BOPLA is inherently destructive — it writes to the target.
**How to avoid:** Destructive gate `opts.destructiveEnabled=false` default prevents stage from running. Runbook warns: "BOPLA modifies server state. Run only on test environments or with authorization."
**Warning signs:** Stage runs when `destructiveEnabled` is not explicitly set to `true`.

### Pitfall 4: Rate-limit test triggering WAF/IP ban

**What goes wrong:** 20 concurrent requests from same source IP triggers WAF block — all subsequent test stages fail with 403/503.
**Why it happens:** Burst is intended saturation — WAF interprets as DDoS.
**How to avoid:** Rate-limit stage runs LAST (or second-to-last before SSRF). 30s inter-API delay. Document in runbook. Single endpoint default limits surface area.
**Warning signs:** POST-burst stages start returning 403/503 for previously 200 endpoints.

### Pitfall 5: SSRF test with interactsh on private network where `oast.me` is blocked

**What goes wrong:** Nuclei spawns and runs SSRF templates but all OOB callbacks fail silently — no findings, no errors.
**Why it happens:** Air-gapped or restricted network cannot reach `oast.me`.
**How to avoid:** Provide `INTERACTSH_URL` env var pointing to self-hosted interactsh. Runbook documents setup: `https://github.com/projectdiscovery/interactsh`.
**Warning signs:** SSRF stage completes with 0 findings even on known-vulnerable targets in dryRun test.

### Pitfall 6: `NucleiFindingSchema` camelCase vs kebab-case

**What goes wrong:** Nuclei JSONL output uses kebab-case fields (`matched-at`, `template-id`, `matcher-name`). The Phase 12 `NucleiFindingSchema` already maps these to camelCase (`matchedAt`, `templateId`, `matcherName`). Accessing `finding['matched-at']` will return `undefined`.
**Why it happens:** Phase 12 STATE.md explicitly documents: "NucleiFinding schema uses camelCase fields (matchedAt/templateId/matcherName) not kebab-case as plan docs showed."
**How to avoid:** Always access parsed JSONL via `safe.data.matchedAt` (not `safe.data['matched-at']`). `ssrfNuclei.ts` parses via the same `NucleiFindingSchema.safeParse()` as `nucleiApi.ts`.

### Pitfall 7: Duplicate findings for BOPLA with same key but different endpoint runs

**What goes wrong:** Dedupe key `(endpointId, category, title)` — BOPLA title includes `{{key}}`. Two runs on the same endpoint with the same key create 1 row (dedupe update). Two runs on the same endpoint with DIFFERENT keys create 2 rows (intended). Make sure `{{key}}` substitution is consistent.
**Why it happens:** Template substitution at title generation time must be deterministic and match exactly the stored title on re-run.
**How to avoid:** Use exact key string from `BOPLA_SENSITIVE_KEYS` array (e.g., `"Campo sensível aceito em PUT/PATCH sem validação (is_admin)"`). Never interpolate with display labels.

---

## Code Examples

### Orchestrator stage skeleton (from apiPassiveTests.ts)
```typescript
// Source: server/services/journeys/apiPassiveTests.ts (Phase 12)
// Pattern replicated in apiActiveTests.ts

export async function runApiActiveTests(
  apiId: string,
  opts: ApiActiveTestOpts,
  jobId?: string,
): Promise<ActiveTestResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const stagesRun: StageName[] = [];
  const stagesSkipped: Array<{ stage: string; reason: string }> = [];
  // ... counters ...
  let cancelled = false;

  const finalize = (): ActiveTestResult => ({
    apiId,
    stagesRun,
    stagesSkipped,
    findingsCreated,
    findingsUpdated,
    findingsByCategory,
    findingsBySeverity,
    cancelled,
    dryRun: opts.dryRun ?? false,
    durationMs: Date.now() - startedAt,
    credentialsUsed,
  });

  const checkCancel = (): boolean => {
    if (jobId && jobQueue.isJobCancelled(jobId)) {
      cancelled = true;
      controller.abort();
      return true;
    }
    return false;
  };

  // Stage: bola
  if (effectiveStages.bola) {
    if (checkCancel()) return finalize();
    try {
      // ... run BOLA ...
      stagesRun.push('bola');
    } catch (err) {
      log.error({ err, apiId, stage: 'bola' }, 'bola stage failed');
      stagesSkipped.push({ stage: 'bola', reason: String(err) });
    }
  }
  // ... repeat for bfla, bopla, rate_limit, ssrf ...

  return finalize();
}
```

### Zod schema for apiActiveTestOptsSchema
```typescript
// Source: Pattern from apiPassiveTestOptsSchema in shared/schema.ts (Phase 12)
export const apiActiveTestOptsSchema = z.object({
  stages: z.object({
    bola: z.boolean().optional(),
    bfla: z.boolean().optional(),
    bopla: z.boolean().optional(),
    rateLimit: z.boolean().optional(),
    ssrf: z.boolean().optional(),
  }).strict().optional(),
  destructiveEnabled: z.boolean().optional(),
  credentialIds: z.array(z.string().uuid()).optional(),
  endpointIds: z.array(z.string().uuid()).optional(),
  dryRun: z.boolean().optional(),
  rateLimit: z.object({
    burstSize: z.number().int().min(1).max(50).optional(),
    windowMs: z.number().int().min(100).optional(),
    endpointIds: z.array(z.string().uuid()).max(5).optional(),
  }).strict().optional(),
  ssrf: z.object({
    interactshUrl: z.string().url().optional(),
  }).strict().optional(),
  bola: z.object({
    maxCredentials: z.number().int().min(2).max(6).optional(),
    maxIdsPerEndpoint: z.number().int().min(1).max(5).optional(),
  }).strict().optional(),
}).strict();
```

### BOLA credential pair generation
```typescript
// Source: CONTEXT.md §BOLA — ordered pairs without mirroring
function pairCredentials(
  creds: ApiCredentialSafe[],
  maxCredentials: number,
): Array<[ApiCredentialSafe, ApiCredentialSafe]> {
  const capped = creds.slice(0, maxCredentials); // max 4 by default
  const pairs: Array<[ApiCredentialSafe, ApiCredentialSafe]> = [];
  for (let i = 0; i < capped.length; i++) {
    for (let j = i + 1; j < capped.length; j++) {
      pairs.push([capped[i], capped[j]]);
    }
  }
  return pairs; // C(n,2) ordered unique pairs
}
```

### Remediation template extensions
```typescript
// Source: CONTEXT.md §Findings dedupe + evidence + remediation
// Extends shared/apiRemediationTemplates.ts (Phase 12)
export const API_REMEDIATION_TEMPLATES = {
  // ... existing Phase 12 entries ...
  api1_bola_2023: 'Implemente verificação de autorização por objeto (object-level ACL) antes de servir recursos. Nunca confie apenas no ID fornecido pelo cliente — valide que o principal autenticado tem permissão no objeto específico.',
  api3_bopla_2023: 'Use allow-list explícita de campos aceitáveis em PUT/PATCH. Rejeite ou ignore silenciosamente propriedades sensíveis (role, is_admin, permissions) mesmo se presentes no payload.',
  api4_rate_limit_2023: 'Implemente rate limiting com respostas 429 Too Many Requests + header Retry-After. Use limites diferenciados por tier de usuário e endpoint.',
  api5_bfla_2023: 'Aplique autorização por função (role-based access control) em todos endpoints administrativos. Valide privilégios no backend mesmo quando a UI não expõe a ação — nunca confie no cliente.',
  api7_ssrf_2023: 'Valide URLs fornecidas pelo usuário contra allow-list explícita de destinos. Bloqueie ranges privados (RFC 1918), localhost, link-local, e cloud metadata endpoints (169.254.169.254). Use client HTTP dedicado sem seguir redirects para metadata.',
} as const;
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Nuclei for all API security tests | Nuclei for stateless (misconfig/exposure) + TypeScript in-house for stateful (BOLA/BFLA/BOPLA) | PROJECT.md key decision (v2.0 design) | Nuclei cannot track multi-credential state; in-house TS can |
| Global `-ni` (no-interactsh) everywhere | `-ni` only in legacy `vulnScanner.ts`; `nucleiApi.ts` and `ssrfNuclei.ts` have no `-ni` | Phase 12 design | Enables SSRF OOB detection in API testing without affecting other scans |
| Single credential per endpoint | Multi-credential pairing (BOLA) + priority ranking (BFLA) | Phase 13 (this phase) | Enables cross-identity authorization bypass detection |

---

## Validation Architecture

`workflow.nyquist_validation` is `true` in `.planning/config.json` — this section is required.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest 4.0.18 |
| Config file | `vitest.config.ts` (existing) |
| Quick run command | `npx vitest run server/__tests__/apiActive/` |
| Full suite command | `npx vitest run` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-03 | `pairCredentials` generates C(n,2) unique ordered pairs | unit | `npx vitest run server/__tests__/apiActive/bola.test.ts` | Wave 0 |
| TEST-03 | `harvestObjectIds` extracts ≤3 IDs from JSON at `id/uuid/pk` keys | unit | `npx vitest run server/__tests__/apiActive/bola.test.ts` | Wave 0 |
| TEST-03 | Cross-access returns BolaHit when cred B gets status < 400 and no forbidden text | unit | `npx vitest run server/__tests__/apiActive/bola.test.ts` | Wave 0 |
| TEST-04 | Low-priv identification: highest priority int wins, description heuristic matches | unit | `npx vitest run server/__tests__/apiActive/bfla.test.ts` | Wave 0 |
| TEST-04 | Admin path regex matches expected paths and rejects non-admin paths | unit | `npx vitest run server/__tests__/apiActive/bfla.test.ts` | Wave 0 |
| TEST-05 | Seed GET + injection + reflection detection returns Bopla hit when key appears in after-GET | unit | `npx vitest run server/__tests__/apiActive/bopla.test.ts` | Wave 0 |
| TEST-05 | Stage skips entirely when `opts.destructiveEnabled !== true` | unit | `npx vitest run server/__tests__/apiActive/bopla.test.ts` | Wave 0 |
| TEST-06 | `buildBurst(20)` issues exactly 20 parallel fetch calls | unit | `npx vitest run server/__tests__/apiActive/rateLimit.test.ts` | Wave 0 |
| TEST-06 | `detectThrottling` returns no-finding when no 429, no Retry-After, no X-RateLimit-*, ≥90% success | unit | `npx vitest run server/__tests__/apiActive/rateLimit.test.ts` | Wave 0 |
| TEST-07 | `identifyUrlParams` matches name regex and example-URL heuristic | unit | `npx vitest run server/__tests__/apiActive/ssrfNuclei.test.ts` | Wave 0 |
| TEST-07 | `buildSsrfNucleiArgs` includes `-interactions-poll-duration`, no `-ni`, includes `-interactsh-url` when env set | unit | `npx vitest run server/__tests__/apiActive/ssrfNuclei.test.ts` | Wave 0 |
| All | `apiActiveTestOptsSchema` accepts valid opts with defaults | unit | `npx vitest run server/__tests__/apiActive/schema.test.ts` | Wave 0 |
| All | `apiActiveTestOptsSchema` rejects `burstSize > 50` with Zod error | unit | `npx vitest run server/__tests__/apiActive/schema.test.ts` | Wave 0 |
| All | `apiActiveTestOptsSchema` rejects `destructiveEnabled` absent when `bopla=true` (default-false gate) | unit | `npx vitest run server/__tests__/apiActive/schema.test.ts` | Wave 0 |
| All | Orchestrator: dryRun loads fixtures for each stage; stage order is bola→bfla→bopla→rate_limit→ssrf; cancelled=true when job cancelled before ssrf | integration | `npx vitest run server/__tests__/apiActive/orchestrator.test.ts` | Wave 0 |

### Sampling Rate

- **Per task commit:** `npx vitest run server/__tests__/apiActive/`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps (all missing — new phase)

- [ ] `server/__tests__/apiActive/schema.test.ts` — covers `apiActiveTestOptsSchema` (3 stubs)
- [ ] `server/__tests__/apiActive/bola.test.ts` — covers TEST-03 (3 stubs)
- [ ] `server/__tests__/apiActive/bfla.test.ts` — covers TEST-04 (2 stubs)
- [ ] `server/__tests__/apiActive/bopla.test.ts` — covers TEST-05 (2 stubs)
- [ ] `server/__tests__/apiActive/rateLimit.test.ts` — covers TEST-06 (2 stubs)
- [ ] `server/__tests__/apiActive/ssrfNuclei.test.ts` — covers TEST-07 (2 stubs)
- [ ] `server/__tests__/apiActive/orchestrator.test.ts` — covers orchestrator (1 stub)
- [ ] `server/__tests__/fixtures/api-active/` directory + 6 fixture files

No framework install needed — Vitest already configured in `vitest.config.ts`.

---

## Open Questions

1. **`listApiCredentialsForApi` as new IStorage method vs inline**
   - What we know: `listApiCredentials({ apiId })` already exists and does what BOLA needs.
   - What's unclear: Whether to add a named wrapper for discoverability.
   - Recommendation: Planner decides — both work equally. Favor inline `listApiCredentials({ apiId })` to avoid IStorage extension overhead in this phase.

2. **BFLA skip condition for "universal credential" — when to activate**
   - What we know: CONTEXT.md specifies the skip condition (low-priv cred passes non-admin endpoints with same success rate as other creds).
   - What's unclear: How many non-admin endpoints to probe as the "control" sample. Too many = extra budget; too few = false positives.
   - Recommendation: Sample 3 random non-admin GET endpoints for the control check. If low-priv succeeds on ≥2/3, flag as "universal credential" and skip BFLA for that cred.

3. **SSRF stage when no URL-like params are found**
   - What we know: Stage should skip with logged reason if `identifyUrlParams` returns empty list.
   - What's unclear: Whether to still run Nuclei with 0 targets (harmless) or skip early.
   - Recommendation: Skip early with `stagesSkipped.push({ stage: 'ssrf', reason: 'no URL-like params found' })`. Avoids unnecessary `preflightNuclei` call.

---

## Sources

### Primary (HIGH confidence)

- `.planning/phases/13-security-testing-active/13-CONTEXT.md` — exhaustive implementation decisions for all 5 vectors
- `server/services/journeys/apiPassiveTests.ts` (Phase 12 code) — direct orchestrator template; read in full
- `server/services/scanners/api/nucleiApi.ts` (Phase 12 code) — SSRF scanner template; confirmed `buildNucleiArgs` does NOT include `-ni`
- `server/services/scanners/api/authFailure.ts` (Phase 12 code) — in-house TS scanner template structure
- `server/storage/apiCredentials.ts` (Phase 10 code) — confirmed `listApiCredentials({ apiId })` exists and returns `ApiCredentialSafe[]`
- `shared/schema.ts` lines 94-110 — confirmed all 5 OWASP categories already in `owaspApiCategoryEnum`
- `shared/schema.ts` lines 1896-1932 — confirmed `apiPassiveTestOptsSchema` pattern for `apiActiveTestOptsSchema`
- `server/__tests__/fixtures/api-passive/nuclei-passive-mock.jsonl` — confirmed Nuclei JSONL shape (camelCase keys via `NucleiFindingSchema`)
- `.planning/STATE.md` — confirmed Phase 12 decisions (NucleiFinding camelCase, upsertApiFindingByKey transaction, decryptCredential signature)
- `server/services/scanners/vulnScanner.ts:130` — confirmed `-ni` flag is only in legacy scanner, NOT in `nucleiApi.ts`
- `.planning/config.json` — confirmed `nyquist_validation: true`

### Secondary (MEDIUM confidence)

- ProjectDiscovery Nuclei docs (referenced in CONTEXT.md `canonical_refs`): `https://docs.projectdiscovery.io/tools/nuclei/usage` — interactsh flags `-interactsh-url`, `-interactions-poll-duration`, `-interactions-wait`, `-interactions-retries-count`; confirming `-ni` disables interactsh and removing it re-enables
- OWASP API Security Top 10 2023: `https://owasp.org/API-Security/editions/2023/en/0x11-t10/` — confirmed API1/API3/API4/API5/API7 category mappings

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new dependencies; all carry-forward from Phase 10/11/12
- Architecture: HIGH — direct template from Phase 12 codebase; code read in full
- Pitfalls: HIGH — most derived from Phase 12 STATE.md decisions and CONTEXT.md constraints; one (Pitfall 4 WAF) is MEDIUM from general security testing knowledge
- Nuclei interactsh flags: HIGH — confirmed from CONTEXT.md canonical_refs pointing to official docs; `buildNucleiArgs` in `nucleiApi.ts` confirmed to not include `-ni`

**Research date:** 2026-04-20
**Valid until:** 2026-05-20 (stable stack; Nuclei template changes don't affect flag syntax)
