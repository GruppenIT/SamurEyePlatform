# Architecture

**Analysis Date:** 2026-03-16

## Pattern Overview

**Overall:** Three-tier web application with monolithic backend + React frontend + PostgreSQL persistence. Client-server separation via REST API with WebSocket for real-time updates.

**Key Characteristics:**
- Frontend and backend bundled as single Express application served on port 5000
- Stateless request handling; database as single source of truth
- Event-driven job execution via in-memory queue (jobQueue service)
- Modular service-oriented design: business logic separated into discrete service layers
- Role-based access control (RBAC) enforced at route and service levels

## Layers

**Presentation Layer (Client):**
- Purpose: React SPA serving security platform UI
- Location: `client/src/`
- Contains: React components, pages, hooks, utility libraries
- Depends on: REST API, WebSocket, TanStack Query
- Used by: End users via HTTP/HTTPS browser

**API Gateway & Routes (Express):**
- Purpose: Request routing, middleware, authentication/authorization
- Location: `server/routes/`
- Contains: Modular route handlers (dashboard, assets, journeys, jobs, threats, users, etc.)
- Depends on: Services, storage layer, middleware
- Used by: Frontend, CLI tools via HTTP/HTTPS

**Service Layer:**
- Purpose: Business logic, orchestration, external integrations
- Location: `server/services/`
- Contains:
  - `journeyExecutor.ts` - Orchestrates attack surface, AD security, EDR/AV journeys
  - `jobQueue.ts` - In-memory job queue with event emissions
  - `threatEngine.ts` - Threat detection, correlation, hibernation logic
  - `cveService.ts` - CVE intelligence, threat matching
  - `hostEnricher.ts` - Host metadata enrichment via SSH/WMI
  - `emailService.ts` - Notification dispatch via SMTP/OAuth2
  - `scheduler.ts` - Schedule-based job triggering
  - `subscriptionService.ts` - License validation, read-only mode
- Depends on: Storage, collectors, scanners, external APIs
- Used by: Routes, scheduler, queue workers

**Scanner/Collector Layer:**
- Purpose: Specialized security tools integration
- Location: `server/services/scanners/`, `server/services/collectors/`
- Contains:
  - `networkScanner.ts` - nmap wrapper for port scanning
  - `vulnScanner.ts` - nuclei wrapper for web vulnerability detection
  - `adScanner.ts` - LDAP/AD analysis and security checks
  - `edrAvScanner.ts` - EDR/AV effectiveness testing (EICAR deployment)
  - `sshCollector.ts` - SSH protocol wrapper
  - `wmiCollector.ts` - Windows RPC/WMI protocol wrapper
- Depends on: External tools, process spawning, network protocols
- Used by: journeyExecutor, hostEnricher

**Storage/Persistence Layer:**
- Purpose: Unified data access interface
- Location: `server/storage/`
- Contains: Modular operation modules (users, assets, hosts, journeys, threats, notifications, etc.)
- Depends on: Drizzle ORM, PostgreSQL
- Used by: Services, routes

**Authentication & Authorization:**
- Purpose: User identity verification, session management, role enforcement
- Location: `server/localAuth.ts`, `server/routes/middleware.ts`
- Contains: Passport.js LocalStrategy, bcryptjs, session persistence
- Depends on: PostgreSQL sessions table
- Used by: All routes via middleware chain

**Real-time Updates:**
- Purpose: Live job/threat updates to connected browsers
- Location: `server/routes/index.ts` (WebSocket server), `client/src/lib/websocket.ts`
- Contains: ws library server, message broadcasting, reconnection logic
- Depends on: jobQueue events
- Used by: Dashboard, jobs page, threats page

## Data Flow

**Job Execution Pipeline:**

1. User creates schedule (POST `/api/schedules`) → stored in DB
2. Scheduler service polls active schedules → enqueues jobs
3. Job handler dequeues → calls journeyExecutor
4. journeyExecutor instantiates appropriate scanner (network/AD/EDR)
5. Scanner spawns subprocess (nmap/nuclei/ldapts/smbclient) → streams results
6. journeyExecutor parses output → creates threats → updates DB
7. jobQueue emits `jobUpdate` event → broadcast via WebSocket → UI re-queries via TanStack Query

**Threat Detection & Correlation:**

1. Scanner discovers vulnerability/misconfiguration
2. threatEngine.detectThreats() creates threat record with severity/type
3. threatEngine correlates with existing threats (deduplication)
4. CVE service enriches with intelligence data
5. Notification service dispatches if rules matched
6. Threat can transition: open → investigating → mitigated → closed (or hibernated/accepted_risk)

**Host Enrichment:**

1. Host discovered during scan → hostEnricher.enrichHost()
2. Attempts SSH/WMI connection using credentials from journey
3. Collects: OS, uptime, services, network config, patch level
4. Stores enrichment record with timestamp
5. Risk history tracks changes over time for trend analysis

**State Management:**

- **Frontend**: TanStack Query for server state (auto-refetch patterns)
- **Backend**: PostgreSQL as SSOT; services maintain in-memory caches (processTracker, jobQueue)
- **Sessions**: PostgreSQL with connect-pg-simple
- **Real-time**: WebSocket broadcasts for live job updates only

## Key Abstractions

**Service Pattern:**
- Purpose: Encapsulate domain logic, callable from routes/scheduler/queue
- Examples:
  - `threatEngine.detectThreats()` - analyzes scan results
  - `hostEnricher.enrichHost()` - gathers host metadata
  - `emailService.sendNotification()` - dispatches alerts
- Pattern: Class-based singleton instances, exported from service module

**Storage Interface (IStorage):**
- Purpose: Abstraction over database operations
- Location: `server/storage/interface.ts`
- Exposes: Modular operation groups (getUsers, getAssets, getThreat, etc.)
- Implementation: `DatabaseStorage` class delegates to submodules

**Journey Execution Model:**
- Purpose: Generalized scanning/testing workflow
- Implementations:
  - `attack_surface`: nmap + nuclei scanning
  - `ad_security`: LDAP queries + PowerShell AD tests
  - `edr_av`: EICAR test files via SMB
  - `web_application`: Web security scanning
- Parameterized: Target selection (individual assets vs. tag-based), credentials mapping, scan settings

**Credential Encryption:**
- Purpose: Secure storage of SSH/WMI/AD passwords
- Location: `server/services/encryption.ts`
- Pattern: DEK/KEK (Data Encryption Key / Key Encryption Key) with AES-256-GCM
- Flow: Plain text → AES encrypt → base64 store → retrieve → decrypt

## Entry Points

**HTTP Server:**
- Location: `server/index.ts`
- Triggers: `npm start` (production) or `npm run dev` (development)
- Responsibilities:
  - Initialize Express app with CORS, JSON parsing
  - Load Drizzle ORM schema from database
  - Start authentication system (Passport.js)
  - Start services (threatEngine, scheduler, subscriptionService)
  - Register route modules
  - Attach WebSocket server
  - Graceful shutdown handlers (SIGTERM, SIGINT)

**Client Entry:**
- Location: `client/src/App.tsx`
- Triggers: Vite dev server or static assets on port 5000
- Responsibilities:
  - Error boundary for rendering crashes
  - Query provider (TanStack Query)
  - Router setup (Wouter)
  - Authentication state via useAuth hook
  - Conditional rendering: unauthenticated → landing/login, authenticated → dashboard

**Route Registration:**
- Location: `server/routes/index.ts` → individual route modules
- Patterns:
  - Each route file exports `registerXxxRoutes(app)`
  - Middleware applied: CORS, JSON parse, auth, subscription check, role check
  - WebSocket handler attached before static file serving

## Error Handling

**Strategy:** Layered error handling with graceful degradation

**Patterns:**

- **Routes**: Try-catch wrapping, return 500 on unhandled, 4xx for validation/auth
- **Services**: Errors propagated to routes; retry logic in specific services (API calls)
- **Database**: Transaction rollback on constraint violations; logs via Drizzle
- **Frontend**: Error boundary component catches render errors; fallback UI shown
- **Jobs**: Timeout protection; failed jobs transitioned to 'failed' status with error log
- **Process Tracking**: Subprocess termination on parent timeout; resource cleanup

## Cross-Cutting Concerns

**Logging:**

- Framework: `pino` for structured JSON logging
- Location: `server/lib/logger.ts` (createLogger utility)
- Output: Console (pretty in dev, JSON in production)
- Scopes: Per-module loggers (e.g., 'threatEngine', 'journeyExecutor', 'routes')

**Validation:**

- Frontend: react-hook-form + Zod schemas
- Backend: Zod schemas from `@shared/schema`, parsed in routes before service calls
- Pattern: Schema-driven PATCH operations with optional fields

**Authentication:**

- Session-based with Passport.js LocalStrategy
- Rate limiting via PostgreSQL (login attempts tracked per email)
- Password hashing via bcryptjs (cost 12)
- Role matrix: global_administrator (all access) > operator (execute/create) > read_only (view only)

**Authorization:**

- Route-level middleware: requireAdmin, requireOperator
- Global middleware: requireActiveSubscription (blocks writes if license expired)
- Implicit: journeyExecutor checks credential availability before scan

**Security Measures (from SECURITY_REMEDIATION_PLAN.md context):**
- CORS origin validation with configurable allowlist
- Subscription-based read-only mode enforcement
- Credential encryption with AES-256-GCM
- Rate limiting on login attempts
- Session expiration
- Password strength enforcement on local auth

---

*Architecture analysis: 2026-03-16*
