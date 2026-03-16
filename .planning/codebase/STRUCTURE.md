# Codebase Structure

**Analysis Date:** 2026-03-16

## Directory Layout

```
SamurEyePlatform/
├── client/                    # React frontend SPA
│   └── src/
│       ├── pages/            # Full-page components (routes)
│       ├── components/       # Reusable UI components
│       │   ├── dashboard/   # Dashboard widget components
│       │   ├── forms/       # Form components (assets, credentials, journeys, etc.)
│       │   ├── layout/      # Top-level layout (sidebar, topbar)
│       │   └── ui/          # shadcn/ui primitives (buttons, dialogs, etc.)
│       ├── hooks/           # Custom React hooks
│       ├── lib/             # Utility functions
│       ├── types/           # TypeScript type definitions
│       └── App.tsx          # Router and error boundary
├── server/                   # Express backend
│   ├── routes/              # Express route handlers (modular)
│   ├── services/            # Business logic and orchestration
│   │   ├── scanners/       # Scanner implementations (nmap, nuclei, LDAP, etc.)
│   │   └── collectors/     # Protocol collectors (SSH, WMI)
│   ├── storage/             # Database access layer
│   ├── lib/                 # Shared server utilities
│   ├── utils/               # Helper functions
│   ├── __tests__/           # Test files
│   ├── index.ts             # Server entry point
│   ├── db.ts                # Drizzle ORM setup
│   ├── localAuth.ts         # Passport.js and session setup
│   └── vite.ts              # Vite integration for dev/build
├── shared/                   # Shared types and schema
│   └── schema.ts            # Drizzle ORM schema + Zod validation
├── scripts/                  # Build and utility scripts
├── package.json             # Dependencies and build scripts
├── tsconfig.json            # TypeScript configuration
├── vite.config.ts           # Vite build configuration
├── vitest.config.ts         # Vitest testing configuration
├── drizzle.config.ts        # Drizzle ORM migration config
└── [docs]                   # Root-level documentation
    ├── README.md
    ├── SECURITY_REMEDIATION_PLAN.md
    └── TESTING.md
```

## Directory Purposes

**client/src/pages/:**
- Purpose: Full-page route components, one per page
- Contains: Page-level state, form containers, data queries
- Key files:
  - `postura.tsx` (dashboard)
  - `assets.tsx` (asset management)
  - `credentials.tsx` (credential vault)
  - `journeys.tsx` (journey builder)
  - `jobs.tsx` (job history/monitoring)
  - `threats.tsx` (threat management)
  - `hosts.tsx` (host inventory)
  - `settings.tsx` (admin settings)
  - `users.tsx` (user management)

**client/src/components/:**
- Purpose: Reusable component library
- `dashboard/`: Widgets for dashboard (metrics-overview, system-health, etc.)
- `forms/`: Form components (asset-form, journey-form, etc.)
- `layout/`: Navigation (sidebar, topbar)
- `ui/`: shadcn/ui library of 30+ primitives

**server/routes/:**
- Purpose: Express route handlers grouped by domain
- Contains: One file per route group (assets, journeys, jobs, threats, users, etc.)
- Pattern: Each exports `registerXxxRoutes(app)` function
- Key files:
  - `index.ts` - Route registration orchestrator, WebSocket setup
  - `assets.ts` - POST/PATCH/DELETE assets and credentials
  - `journeys.ts` - Journey CRUD and execution
  - `jobs.ts` - Job queries and cancellation
  - `threats.ts` - Threat queries, status updates, hibernation
  - `hosts.ts` - Host queries and enrichment
  - `admin.ts` - System settings, subscription, telemetry
  - `users.ts` - User management (admin only)
  - `dashboard.ts` - Dashboard metrics and health
  - `reports.ts` - Report generation

**server/services/:**
- Purpose: Business logic, separated by concern
- Key classes/exports:
  - `journeyExecutor.ts` - Executes scan journeys (attack_surface, ad_security, edr_av, web_application)
  - `threatEngine.ts` - Threat detection, correlation, severity calculation
  - `jobQueue.ts` - EventEmitter-based job queue, tracks running jobs
  - `cveService.ts` - CVE database queries, threat enrichment
  - `hostEnricher.ts` - Collects host metadata via SSH/WMI
  - `emailService.ts` - SMTP/OAuth2 email dispatch
  - `hostService.ts` - Host inventory operations
  - `scheduler.ts` - Cron-like schedule polling
  - `subscriptionService.ts` - License validation, heartbeat to console
  - `settingsService.ts` - System settings CRUD
  - `notificationService.ts` - Notification rule evaluation
  - `systemUpdateService.ts` - Upgrade/rollback operations
  - `processTracker.ts` - Subprocess lifecycle tracking

**server/services/scanners/:**
- Purpose: Integration with external security tools
- Exports: Classes implementing scan interfaces
- Files:
  - `networkScanner.ts` - nmap spawning, port/service parsing
  - `vulnScanner.ts` - nuclei spawning, template management
  - `adScanner.ts` - LDAP queries via ldapts library
  - `edrAvScanner.ts` - SMB deployment of EICAR test files

**server/services/collectors/:**
- Purpose: Protocol implementations for remote data collection
- Files:
  - `sshCollector.ts` - SSH exec via ssh2 library
  - `wmiCollector.ts` - WMI queries via Node.js child_process + PowerShell

**server/storage/:**
- Purpose: Single interface to database operations
- Pattern: Modular exports per entity type
- Files:
  - `index.ts` - DatabaseStorage class aggregating all operations
  - `interface.ts` - IStorage interface definition
  - `users.ts` - User CRUD, login attempts, role updates
  - `assets.ts` - Assets and credentials operations
  - `journeys.ts` - Journeys, schedules, jobs, credentials mapping
  - `hosts.ts` - Host CRUD, enrichment, AD security results
  - `threats.ts` - Threat CRUD, status transitions, hibernation
  - `notifications.ts` - Notification records
  - `settings.ts` - System settings KV store
  - `subscription.ts` - License configuration
  - `sessions.ts` - Session store for Passport.js
  - `database-init.ts` - Database structure initialization

**server/lib/:**
- Purpose: Shared utilities
- Files:
  - `logger.ts` - pino logger factory with per-module scoping

**shared/:**
- Purpose: Shared schema and types across client/server
- Files:
  - `schema.ts` - Drizzle ORM table definitions + Zod validation schemas

## Key File Locations

**Entry Points:**
- `server/index.ts` - HTTP server startup, service initialization, route registration
- `client/src/App.tsx` - React root, router, error boundary
- `package.json` scripts: `npm run dev` (watch), `npm run build` (production), `npm start`

**Configuration:**
- `.env` - Database URL, encryption key, OIDC, SMTP settings
- `tsconfig.json` - Path aliases (@/* for client/src/*, @shared/* for shared/)
- `vite.config.ts` - Vite bundling, React plugin
- `drizzle.config.ts` - Database connection for migrations

**Core Logic:**
- `server/services/journeyExecutor.ts` - Orchestrates all scan types (2000+ lines)
- `server/services/threatEngine.ts` - Threat creation/correlation logic (1700+ lines)
- `shared/schema.ts` - 30+ Drizzle tables + Zod schemas

**Testing:**
- `server/__tests__/` - Vitest test files
- `vitest.config.ts` - Test runner configuration

## Naming Conventions

**Files:**

- **Routes**: `[entity]Routes.ts` or `[domain].ts` (e.g., `assets.ts`, `journeys.ts`)
- **Services**: `[concern]Service.ts` (e.g., `threatEngine.ts`, `emailService.ts`)
- **Scanners**: `[tool]Scanner.ts` (e.g., `networkScanner.ts`, `vulnScanner.ts`)
- **Collectors**: `[protocol]Collector.ts` (e.g., `sshCollector.ts`, `wmiCollector.ts`)
- **Storage modules**: `[entity].ts` (e.g., `users.ts`, `threats.ts`)
- **Pages**: `[feature].tsx` (e.g., `journeys.tsx`, `threats.tsx`)
- **Components**: `[descriptive-name].tsx` (e.g., `active-jobs.tsx`, `metrics-overview.tsx`)
- **Test files**: `[unit].test.ts` or `[unit].spec.ts`

**Directories:**

- Plural for collections: `services/`, `routes/`, `scanners/`, `collectors/`, `pages/`, `components/`
- Lowercase with hyphens: `client/src/components/`, `server/services/scanners/`

**Functions/Variables:**

- camelCase for functions and variables
- PascalCase for classes and types (Zod schemas, React components)
- UPPERCASE for constants (enum values match database enums)

**Database:**

- snake_case for columns: `created_at`, `password_hash`, `user_account_control`
- PascalCase for TypeScript mapped types: `User`, `Asset`, `Journey`
- Enum types: snake_case prefix + values in quotes (e.g., `user_role` enum with 'global_administrator')

## Where to Add New Code

**New Feature (e.g., new scan type):**
- Primary code:
  - Scanner: `server/services/scanners/[toolName]Scanner.ts`
  - Executor integration: Add handler in `server/services/journeyExecutor.ts`
  - Route handler: `server/routes/journeys.ts` or new `server/routes/[feature].ts`
  - Database schema: Add table in `shared/schema.ts`
  - Storage ops: New file `server/storage/[entity].ts` or extend existing module
- Tests: `server/__tests__/[feature].test.ts`

**New Component/UI:**
- Implementation: `client/src/components/[category]/[component-name].tsx`
- If full-page: `client/src/pages/[page-name].tsx`
- Add route in `client/src/App.tsx` Router
- Use shadcn/ui primitives from `client/src/components/ui/`

**New Service (business logic):**
- Implementation: `server/services/[serviceName].ts`
- Singleton export at module bottom
- Called from routes or scheduler
- Add to initialization in `server/index.ts` if requires startup (e.g., schedulerService.start())

**Utilities:**
- Shared (client + server): `shared/` (be cautious of bloat)
- Server-only: `server/lib/` or `server/utils/`
- Client-only: `client/src/lib/`

**Database Migration:**
- Add table/column to `shared/schema.ts`
- Run `npm run db:push` to migrate (Drizzle in push mode)
- Add storage operations to corresponding file in `server/storage/`

## Special Directories

**server/storage/:**
- Purpose: Database access abstraction
- Generated: No (hand-written)
- Committed: Yes
- Pattern: Each module handles one entity group (users, assets, threats, etc.)
- Exports: IStorage interface + DatabaseStorage implementation

**client/src/components/ui/:**
- Purpose: Shadcn/ui component library
- Generated: Yes (copied from shadcn template)
- Committed: Yes
- Customization: Modify via Tailwind CSS classes; don't delete

**server/services/scanners/, server/services/collectors/:**
- Purpose: Tool integrations and protocol wrappers
- Generated: No (hand-written)
- Committed: Yes
- Process spawning: Uses child_process.spawn with error handling and resource cleanup

**shared/schema.ts:**
- Purpose: Single source of truth for database + validation
- Generated: No (hand-written Drizzle + Zod schemas)
- Committed: Yes
- Pattern: Drizzle tables define DB structure; Zod schemas validate API payloads

**vite.config.ts, drizzle.config.ts:**
- Purpose: Build and ORM tooling configuration
- Generated: No
- Committed: Yes
- Changes require rebuild/migrations to take effect

---

*Structure analysis: 2026-03-16*
