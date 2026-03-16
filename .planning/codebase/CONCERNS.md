# Codebase Concerns

**Analysis Date:** 2026-03-16

## Tech Debt

**Large Monolithic Components:**
- Issue: `adScanner.ts` (1937 lines), `threatEngine.ts` (1832 lines), `journeyExecutor.ts` (1812 lines), and client pages like `hosts.tsx` (1487 lines) are complex and difficult to maintain
- Files: `server/services/scanners/adScanner.ts`, `server/services/threatEngine.ts`, `server/services/journeyExecutor.ts`, `client/src/pages/hosts.tsx`, `client/src/pages/threats.tsx`
- Impact: High risk of regression when modifying these files; difficult to test individual functions; cognitive load makes bugs more likely
- Fix approach: Break into smaller, single-responsibility modules. Extract AD test metadata, threat rule logic, journey stages into separate concerns. Split React pages into smaller components.

**Weak Type Safety with `any` Types:**
- Issue: ~60+ instances of `any` type used throughout codebase (`req: any`, `error: any`, `findings: any[]`, `props: Record<string, any>`)
- Files: `server/routes/users.ts`, `server/routes/threats.ts`, `server/routes/hosts.ts`, `server/index.ts`, `server/services/threatEngine.ts`
- Impact: Loss of TypeScript protection; runtime errors that could be caught at compile time; harder refactoring
- Fix approach: Remove all `any` types. Use proper type definitions. Use `unknown` if type is genuinely unknown, then narrow with type guards. Start with routes that handle user input.

**Incomplete Error Handling in Scanner Services:**
- Issue: Scanner services (nmap, nuclei, PowerShell) spawn child processes but error recovery is inconsistent. Some errors result in empty arrays `[]`, others throw, others log and continue
- Files: `server/services/scanners/vulnScanner.ts` (lines 68-100), `server/services/scanners/adScanner.ts` (lines 400-480), `server/services/journeyExecutor.ts` (lines 544-558)
- Impact: Unclear failure modes when tools crash/timeout; silent failures mask infrastructure problems; operators don't know if "no findings" means "nothing found" or "scanner failed"
- Fix approach: Standardize error handling: (1) Always distinguish between "no results" and "error occurred" (2) Wrap all spawned process calls with consistent error classification (3) Return error metadata alongside findings (4) Add job status like `partial_failure` for recoverable errors

**Development Mode Encryption Key Weakness:**
- Issue: `encryption.ts` line 30 uses hardcoded derivation key `scryptSync('samureye-dev-key', 'salt', KEY_LENGTH)` in non-production when `ENCRYPTION_KEK` is missing
- Files: `server/services/encryption.ts`
- Impact: If someone accidentally runs production without setting `ENCRYPTION_KEK`, credentials are encrypted with predictable key; stored credentials become insecure
- Fix approach: (1) Fail fast in startup validation - throw error if production without `ENCRYPTION_KEK` (2) Use randomly generated ephemeral key if dev mode without env var (3) Add server startup checklist that validates all critical env vars exist

**Unvalidated CVE Matching Logic:**
- Issue: CVE service matches vulnerabilities against CPE lists but comment on line 270 indicates "iterates ALL CPEs before deciding, prioritizing positive matches" - logic may be complex/inefficient
- Files: `server/services/cveService.ts` (lines 270-347)
- Impact: False positives/negatives in CVE detection; potentially slow matching for hosts with many services; difficult to debug CVE mismatches
- Fix approach: (1) Add detailed matching logs showing why each CVE matched/didn't match (2) Create test cases with known vulnerable versions (3) Profile matching performance with large CPE lists (4) Add confidence score explaining match certainty

## Known Bugs

**Race Condition in Job Status Updates:**
- Symptoms: Job progress reported via WebSocket may be inconsistent with database state. Process updates and job updates can arrive out of order
- Files: `server/services/jobQueue.ts` (lines 50-93), `server/services/processTracker.ts`
- Trigger: Long-running journeys with frequent process status updates. WebSocket subscriber may see progress 80% then 50% then 90%
- Workaround: Client-side caches highest progress seen; WebSocket updates filtered by timestamp
- Fix approach: Add monotonic version numbers to all job status updates. Enforce at database level that updates are applied serially. Include expected previous state in updates to detect races.

**Null Pointer Risk in CVE Result Filtering:**
- Symptoms: `cveService.searchCVEs()` returns `null` from `filterCVEsByVersion()` at line 347 without null checks
- Files: `server/services/cveService.ts` (lines 94, 114, 142, 347)
- Trigger: When cache returns results but subsequent filtering returns null
- Workaround: None; returns `null` to caller which must handle
- Fix approach: Always return empty array `[]` instead of `null`. Update `CVEResult[]` return type guarantees never null.

**Database Query Without Null Checks:**
- Symptoms: `findHostByTarget()` can return undefined but some callers don't check
- Files: `server/storage/hosts.ts` (lines 168, 96), `server/services/journeyExecutor.ts` (line 504)
- Trigger: Asset lookup in journey executor assumes asset exists; will crash if asset was deleted between job creation and execution
- Workaround: None detected
- Fix approach: Add defensive null checks in journey executor before using assets. Consider soft-delete pattern for assets used in journeys.

**PowerShell Output Parsing Assumes Valid JSON:**
- Symptoms: AD security test results parsing in `adScanner.ts` assumes PowerShell output contains JSON, but if test returns plain text or XML, parser fails silently or throws unhandled error
- Files: `server/services/scanners/adScanner.ts` (lines 350-400 region)
- Trigger: Custom PowerShell scripts that return non-JSON output; network issues truncating output
- Workaround: None; falls back to creating error finding
- Fix approach: (1) Add schema validation to PowerShell output before parsing (2) Add sample PowerShell script execution output to tests (3) Validate all test metadata matches actual PowerShell template expectations

## Security Considerations

**Session Invalidation on Startup Doesn't Cover Distributed Deployments:**
- Risk: `invalidateAllSessionsOnStartup()` in `localAuth.ts` (lines 113-137) increments session version but only deletes from one instance. In multi-instance deployments, other instances still serve old sessions
- Files: `server/localAuth.ts` (lines 113-137), `server/storage/database-init.ts`
- Current mitigation: Single-instance assumption; session version check prevents usage of truly stale sessions
- Recommendations: (1) Use distributed session invalidation timestamp stored in database (2) All instances check this timestamp and reject older session versions (3) Implement graceful degradation where instances restart with new version

**CORS Configuration Not Enforced at Route Level:**
- Risk: CORS check happens at Express middleware level but individual routes that serve sensitive data don't validate origin
- Files: `server/index.ts` (lines 19-30), `server/routes/*.ts` - no per-route CORS checks
- Current mitigation: CORS middleware on all routes
- Recommendations: (1) Add explicit origin validation on sensitive endpoints (credentials, journeys, admin) (2) Implement stricter CORS for admin routes (3) Log all cross-origin requests for audit

**Credential Storage Decryption Without Access Control:**
- Risk: Once a credential is decrypted in memory via `encryptionService.decryptCredential()`, it's a plain string in `journeyExecutor` passed to scanner services. If scanner process crashes/core dumps, credential appears in memory
- Files: `server/services/journeyExecutor.ts` (lines 603-606), `server/services/scanners/adScanner.ts` (line 640+)
- Current mitigation: Credentials marked as sensitive in logger; process runs with restricted permissions
- Recommendations: (1) Use secure string buffers that zero memory on GC (node doesn't support this natively) (2) Immediately null/delete credential strings after use (3) Consider calling credentials via API rather than direct process invocation (4) Add security.txt documenting credential handling

**Default Test Filtering May Hide Failures:**
- Risk: `adScanner.ts` line 468-470 throws error only if ALL tests fail with credential error, but partial failures (7 of 10 pass) don't raise alarms
- Files: `server/services/scanners/adScanner.ts` (lines 468-477)
- Current mitigation: Individual test results marked as 'error' status
- Recommendations: (1) Track failure rate threshold (e.g., >20% errors = job incomplete) (2) Audit logs should flag high error rates (3) Journey status should reflect "partial_failure" not just "completed"

**Weak Rate Limiting on Login:**
- Risk: Rate limiting uses database checks `SELECT COUNT(*) FROM login_attempts` but no distributed lock. Concurrent requests can bypass limits
- Files: `server/localAuth.ts` (line 416), `server/storage/*.ts`
- Current mitigation: PostgreSQL serializable isolation helps but not explicit synchronization
- Recommendations: (1) Use Redis-backed distributed rate limit if multi-instance (2) Add Lua-script-based atomic counters (3) Implement exponential backoff (2s, 4s, 8s) per IP+user combo (4) Add alerting for brute force attempts

## Performance Bottlenecks

**Full AD Scan Blocks on Single Domain Query:**
- Problem: `adScanner.scanADSecurity()` calls PowerShell which queries entire domain for all categories sequentially. On large domains (10k+ users), this can take 30+ minutes
- Files: `server/services/scanners/adScanner.ts` (lines 200-480)
- Cause: No parallelization of LDAP category queries; PowerShell scripts run linearly
- Improvement path: (1) Parallelize category queries up to 3 concurrent (2) Add pagination for large result sets (3) Implement streaming results back to client instead of buffering all in memory (4) Add timeout per category with partial results

**CVE Database Fetching Causes Network Latency:**
- Problem: `cveService.searchCVEs()` makes HTTP requests to NVD API per service/version combo. With 100+ services detected per network, results in 100+ sequential API calls at 6s rate limit = 10+ minutes
- Files: `server/services/cveService.ts` (lines 59, 100, 869)
- Cause: Rate limiting (6s between requests); caching key is `service:version` so different versions of same service = different lookups
- Improvement path: (1) Increase in-memory cache lifetime (currently expires after process restart) (2) Use Redis for shared cache across instances (3) Batch NVD requests if API supports multi-lookup (4) Pre-cache common services/versions

**Memory Accumulation in Long-Running Journeys:**
- Problem: `journeyExecutor.executeJourney()` accumulates findings in memory: `const findings = []` growing unbounded until job completes
- Files: `server/services/journeyExecutor.ts` (lines 521, 545, 568)
- Cause: Process stdout/stderr stored in memory before writing to database; large nmap scans (1000+ hosts) or nuclei results (10k+ findings) consume GBs
- Improvement path: (1) Stream findings to database immediately instead of buffering (2) Implement circular buffer for recent findings (3) Add memory monitoring that dumps in-flight data to disk if >1GB (4) Paginate results returned to API instead of full dump

**Frontend Re-renders All Hosts on Any Update:**
- Problem: `hosts.tsx` likely re-queries all hosts and re-renders full table on each threat update, socket message, or status change
- Files: `client/src/pages/hosts.tsx` (1487 lines)
- Cause: Likely uses `useQuery` without proper query key scoping or cache invalidation strategy
- Improvement path: (1) Use React Query's fine-grained invalidation (specific host IDs) (2) Implement virtual scrolling for 1000+ hosts (3) Use local optimistic updates for status changes (4) Debounce bulk operations

## Fragile Areas

**AD Security Test Metadata Hardcoded in Code:**
- Files: `server/services/scanners/adScanner.ts` (lines 300-370 region with test IDs, names, categories)
- Why fragile: Test names, categories, severity levels scattered throughout file; PowerShell template changes require code changes; no schema validation between code and actual PowerShell scripts
- Safe modification: (1) Extract all test metadata to JSON config file `config/ad-security-tests.json` (2) Load and validate on startup (3) Update code to reference config by test ID only (4) Add test to verify metadata completeness
- Test coverage: No tests validating metadata matches PowerShell output format

**Journey Executor Stage Transitions Not Validated:**
- Files: `server/services/journeyExecutor.ts` (lines 80-98 switch statement, lines 200-650 stage implementations)
- Why fragile: Stages call each other directly without state machine validation; missing `onProgress` calls; error in one stage leaves job in unknown state
- Safe modification: (1) Create explicit state machine with valid transitions (2) Wrap each stage in try-finally that records completion (3) Add integration tests for each stage transition (4) Implement state validation checkpoints
- Test coverage: Individual stage tests exist but no multi-stage integration tests

**Database Connection Pooling Relies on Default Config:**
- Files: `server/db.ts` (line 11), `server/index.ts` (lines 171-172)
- Why fragile: No explicit pool size configuration; relies on `pg` library defaults; no monitoring of active connections
- Safe modification: (1) Explicit pool config with maxClients=20 (2) Add graceful shutdown timeout (3) Log pool events (connect, error, idle client removal) (4) Add metrics endpoint exposing pool state
- Test coverage: No pool exhaustion tests

**Encryption Key Migration Path Missing:**
- Files: `server/services/encryption.ts` (lines 12-31)
- Why fragile: If KEK needs rotation, no migration strategy for credentials encrypted with old key; rotating key requires decrypting all creds and re-encrypting
- Safe modification: (1) Add `createdWithKeyVersion` field to credentials (2) Support multiple KEKs keyed by version (3) Implement background migration job (4) Add tests for cross-version decryption
- Test coverage: No key rotation tests

## Scaling Limits

**Job Queue Hardcoded Concurrency:**
- Current capacity: 3 concurrent journeys (line 26 `maxConcurrentJobs = 3`)
- Limit: With larger deployments or longer-running scans, queue fills up and users see "queue full" errors after 3+ jobs
- Scaling path: (1) Make `maxConcurrentJobs` configurable via env var (2) Add queue monitoring metrics (3) Implement adaptive concurrency based on memory/CPU (4) Add queue length limits with backpressure to reject new jobs

**NVD CVE API Rate Limiting:**
- Current capacity: 6 seconds between requests = ~600 CVE lookups per hour
- Limit: Large scans detecting 200+ services exceed limit; requests timeout or hit rate limits
- Scaling path: (1) Implement request queuing with jitter (2) Use bulk/batch endpoints if NVD provides (3) Cache at network level (Redis) shared across instances (4) Consider mirror API if available

**PostgreSQL Connection Pool:**
- Current capacity: Driver defaults to 10 connections; configurable but not exposed
- Limit: With 3 concurrent journeys each using 5-10 queries = 30 queries queued; slow responses
- Scaling path: (1) Explicit pool config with max=30 (2) Add connection pool metrics (3) Implement query timeout (4) Consider read replicas for reporting queries

**Single Database Instance:**
- Current capacity: Single PostgreSQL instance handles all reads/writes
- Limit: With high concurrent threats/hosts updates, database CPU maxes out; writes block readers
- Scaling path: (1) Identify read-heavy queries (hosts list, threats stats) (2) Add read replica for reporting (3) Implement write batching in threat engine (4) Consider event sourcing for audit logs

## Dependencies at Risk

**nmap/nuclei External Tool Dependency:**
- Risk: Scans fail silently if tools not installed; no version verification; malicious `PATH` can execute wrong binary
- Impact: `journeyExecutor` can't run network/vulnerability scans; renders features unavailable
- Migration plan: (1) Vendor nmap/nuclei binaries in Docker image with checksums (2) Add startup verification: `nmap --version` (3) Hash-verify binaries before execution (4) Implement fallback scanner if tools missing

**NVD API Service Availability:**
- Risk: NVD API slowness/downtime blocks CVE lookups; rate limits cause cascading failures
- Impact: Vulnerabilities can't be identified; gap in security visibility
- Migration plan: (1) Cache aggressively with 24h TTL (2) Implement graceful degradation (serve stale cache if API down) (3) Add monitoring/alerting on API response times (4) Consider alternative CVE sources (OSV, VulnDB)

**PostgreSQL as Single Point of Failure:**
- Risk: Database down = entire platform down; no backup mechanism for journeys in flight
- Impact: Running scans interrupted; state loss; users can't save findings
- Migration plan: (1) Daily automated backups to S3 (2) Implement replication for HA (3) Add persistent queue for journeys (message broker) (4) Checkpoint journey state periodically

## Test Coverage Gaps

**Network Scanner Output Parsing Not Tested:**
- What's not tested: nmap XML parsing edge cases (malformed XML, huge port lists, timeout scenarios)
- Files: `server/services/scanners/networkScanner.ts`
- Risk: Parser crashes or produces garbage output on malformed nmap results; users see empty host lists
- Priority: High

**AD Test Result Parsing Not Tested:**
- What's not tested: PowerShell JSON output variations (null fields, array vs single object, Unicode in strings)
- Files: `server/services/scanners/adScanner.ts` (lines 350-400 parsing region)
- Risk: Valid test results silently fail to parse; findings appear as 'error' status
- Priority: High

**Threat Rule Matching Not Tested:**
- What's not tested: Edge cases in threat engine matcher logic; competing rules matching same finding; edge cases in service classification (e.g., port 80 classified as other if no service name)
- Files: `server/services/threatEngine.ts` (lines 81-96 classification, rules 100+)
- Risk: Inconsistent threat detection; different findings get different severities unpredictably
- Priority: Medium

**Client State Management Under Network Delay:**
- What's not tested: Rapid state changes while network is slow (mark threat resolved, change status, update twice before response); race conditions in bulk operations
- Files: `client/src/pages/threats.tsx` (lines 80-200+ state management)
- Risk: UI shows inconsistent state; user confusion about what was actually saved
- Priority: Medium

**Credential Encryption Round-Trip:**
- What's not tested: Large credentials (>1KB); special characters in passwords; Unicode passwords; decryption after long storage times
- Files: `server/services/encryption.ts`, `server/__tests__/encryption.test.ts`
- Risk: Some credentials fail to decrypt; users can't authenticate to targets
- Priority: High

**Journey Execution Error Recovery:**
- What's not tested: Mid-journey failures (stage 2 fails, stage 3 starts anyway); credential validation failures; network timeouts during asset enrichment
- Files: `server/services/journeyExecutor.ts` (no error recovery tests)
- Risk: Partial jobs marked as completed; orphaned processes running after job fails
- Priority: Critical

---

*Concerns audit: 2026-03-16*
