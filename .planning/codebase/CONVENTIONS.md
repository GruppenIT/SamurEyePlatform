# Coding Conventions

**Analysis Date:** 2026-03-16

## Naming Patterns

**Files:**
- Services: PascalCase with 'Service' suffix. Examples: `encryption.ts`, `emailService.ts`, `hostService.ts`
- Routes: lowercase with domain name. Examples: `admin.ts`, `assets.ts`, `credentials.ts`, `journeys.ts`
- Utilities: lowercase descriptive names. Examples: `winrm-wrapper.py` (hyphenated)
- Components (client): kebab-case. Examples: `active-jobs.tsx`, `credential-form.tsx`, `dashboard.tsx`
- Test files: matching source file name with `.test.ts` suffix. Example: `encryption.test.ts`, `logger.test.ts`

**Functions:**
- camelCase for all functions. Examples: `createLogger()`, `encryptCredential()`, `normalizeHostName()`, `determineHostType()`
- Async functions: same camelCase. Examples: `getSystemMetrics()`, `registerRoutes()`, `startHibernationMonitor()`
- Private methods: prefix with underscore. Example: `_normalizeHostName()`, `_determineHostType()`
- Handler functions: use verb-noun pattern. Examples: `corsOriginCheck()`, `validateCredential()`, `parseCookies()`

**Variables:**
- camelCase for all variables. Examples: `testTimeout`, `allowedOrigins`, `emailSettings`, `isDev`
- Constants: UPPER_SNAKE_CASE. Examples: `ALGORITHM`, `IV_LENGTH`, `KEY_LENGTH`, `TAG_LENGTH`, `REDACT_PATHS`
- Type/interface names: PascalCase. Examples: `HostType`, `HostFamily`, `ErrorBoundaryState`, `EmailOptions`
- Private class members: prefixed with underscore. Example: `this.kek`

**Types:**
- Interface definitions: `interface NamePattern {}` — typically used for external contracts
- Type aliases: `type NamePattern = 'value1' | 'value2';` — typically for enums/unions
- Examples from codebase:
  - `type HostType = 'server' | 'desktop' | 'firewall' | ...`
  - `type HostFamily = 'linux' | 'windows_server' | ...`
  - `export interface HostDiscoveryResult { ... }`
  - `export interface EmailOptions { ... }`

## Code Style

**Formatting:**
- No explicit formatter configured (no .prettierrc found)
- Indentation: 2 spaces (inferred from source files)
- Line length: follows natural breaks, no enforced limit

**Linting:**
- No ESLint configuration detected (.eslintrc not found)
- TypeScript strict mode enabled in `tsconfig.json`:
  - `"strict": true` enforces all type safety checks
  - `"noEmit": true` — type checking only, no output
  - `"esModuleInterop": true` for CommonJS interop

**TypeScript Configuration:**
- Module system: `"module": "ESNext"` with `"type": "module"` in package.json (ES modules throughout)
- Resolution: `"moduleResolution": "bundler"` for modern bundler semantics
- Path aliases configured:
  - `@/*` → `./client/src/*` (client-side imports)
  - `@shared/*` → `./shared/*` (shared schema and types)
- Library targets: `"lib": ["esnext", "dom", "dom.iterable"]` (Node + browser APIs)

## Import Organization

**Order:**
1. External packages (Node.js and npm modules)
   ```typescript
   import express, { type Request, Response, NextFunction } from "express";
   import cors from "cors";
   import crypto from 'crypto';
   import pino from 'pino';
   ```

2. Internal imports (relative paths and aliases)
   ```typescript
   import { storage } from "../storage";
   import { createLogger } from "../lib/logger";
   import { registerDashboardRoutes } from "./dashboard";
   import { activateApplianceSchema } from "@shared/schema";
   import { useAuth } from "@/hooks/useAuth";
   ```

3. Type imports (when possible, use `import type`)
   ```typescript
   import type { Express } from "express";
   import type { Request, Response } from "express";
   import { type Host, type InsertHost } from '@shared/schema';
   ```

**Path Aliases:**
- Use `@shared/*` for types and schemas in `shared/` directory
- Use `@/*` for client-side component imports in `client/src/`
- Use relative paths `../` for same-package imports within `server/`

**Type imports:**
- Always use `import type { ... }` for type-only imports to improve treeshaking
- Example: `import type { InsertHost, Host } from '@shared/schema';`

## Error Handling

**Patterns:**
- Wrap async operations in try/catch blocks
- Log errors with context before returning HTTP response
- Use `log.error({ err: error }, 'message')` pattern with structured logging
- Return user-friendly error messages in Portuguese (e.g., "Falha ao buscar métricas do sistema")

**Route Error Handling:**
```typescript
app.get('/api/endpoint', async (req, res) => {
  try {
    const result = await storage.getSomething();
    res.json(result);
  } catch (error) {
    log.error({ err: error }, 'failed to fetch something');
    res.status(500).json({ message: "Falha ao buscar dados" });
  }
});
```

**Service Error Handling:**
- Throw meaningful errors with context
- Wrap exceptions in try/catch with descriptive messages
- Example from `encryption.ts`:
  ```typescript
  try {
    // operation
  } catch (error) {
    throw new Error(`Falha ao criptografar credencial: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
  }
  ```

**Constructor/Initialization:**
- Throw errors if critical environment variables are missing
- Example from `encryption.ts`:
  ```typescript
  if (process.env.NODE_ENV === 'production' && !kekHex) {
    throw new Error('ENCRYPTION_KEK must be set in production environment');
  }
  ```

## Logging

**Framework:** pino (JSON logger with development-friendly pretty-printing)
- Production: newline-delimited JSON (compatible with ELK, Loki)
- Development: pretty-printed readable output via `pino-pretty`

**Creation Pattern:**
```typescript
import { createLogger } from '../lib/logger';
const log = createLogger('componentName');  // e.g., 'routes:admin', 'encryption', 'hostService'
```

**Usage Patterns:**
```typescript
log.info('simple message');
log.info({ host, duration }, 'scan complete');  // structured data + message
log.warn({ origin }, 'CORS rejected origin');
log.error({ err: error }, 'operation failed');  // always pass error as `err` field
```

**Automatic Redaction:**
- Pino automatically redacts sensitive paths from ALL log output
- Redacted fields: `password`, `secret`, `token`, `apiKey`, `secretEncrypted`, `dekEncrypted`, `cookie`, `authorization`, and nested variants
- Zero performance cost (redaction happens at serialization time)
- Checked in tests: `server/__tests__/logger.test.ts`

**Log Levels:**
- Configurable via `LOG_LEVEL` env var (default: `info`)
- Level hierarchy: `fatal` > `error` > `warn` > `info` > `debug` > `trace`
- Development default: `info`; use `LOG_LEVEL=debug` for verbosity

## Comments

**When to Comment:**
- Document FND (Found issue) patterns with structured comments. Example from `server/index.ts`:
  ```typescript
  // FND-003: CORS configurável — rejeita origens desconhecidas por padrão.
  // Configure via ALLOWED_ORIGINS env var (comma-separated).
  ```
- Document complex algorithms or non-obvious decisions
- Explain workarounds or temporary solutions
- Security-relevant context (e.g., why a check is needed)

**JSDoc/TSDoc:**
- Used for public APIs and service methods
- Format:
  ```typescript
  /**
   * Creates a child logger scoped to a specific component/module.
   *
   * @param component - Short name identifying the module (e.g. 'edrScanner', 'routes')
   * @returns A pino child logger with the component name baked into every log line
   *
   * @example
   * const log = createLogger('subscriptionService');
   * log.info({ url }, 'heartbeat sent');
   */
  export function createLogger(component: string): pino.Logger { ... }
  ```

**Example from codebase:**
```typescript
// From server/lib/logger.ts — structured documentation
// Paths whose values are replaced with "[REDACTED]" in every log entry.
// Uses pino's built-in redaction (zero-copy, no perf hit on hot path).
// Covers nested objects and arrays automatically.
```

## Function Design

**Size:**
- Most functions: 10–50 lines of business logic
- Large services (e.g., `threatEngine.ts`, `journeyExecutor.ts`) may exceed 100 lines for complex orchestration
- Complex functions broken into private helper methods (e.g., `determineHostType()` calls `_hasFirewallIndicators()`)

**Parameters:**
- Avoid long parameter lists; use object destructuring for options
- Example pattern not found in codebase, but TypeScript typing enforces contracts

**Return Values:**
- Functions return explicit types (TypeScript strict mode)
- Async functions return Promises: `async function name(): Promise<ReturnType> { ... }`
- Errors propagated via throw, not null/undefined returns
- Pattern: functions either succeed (return value) or throw

**Exported Functions:**
- Prefix with `export` keyword explicitly
- Use named exports; barrel files aggregate exports
- Example: `export function registerRoutes(app: Express): Promise<Server> { ... }`

## Module Design

**Exports:**
- Services export class instances or factory functions
- Example from `encryption.ts`:
  ```typescript
  export class EncryptionService {
    constructor() { this.kek = getKEK(); }
    encryptCredential(secret: string) { ... }
  }
  ```

**Singleton Pattern:**
- Services typically instantiated as singletons in `server/index.ts`
- Example: `const encryptionService = new EncryptionService();`
- Passed to routes/handlers via injection

**Barrel Files:**
- Route registration follows barrel pattern: `routes/index.ts` imports all route modules and calls `register*Routes(app)`
- Example from `server/routes/index.ts`:
  ```typescript
  registerDashboardRoutes(app);
  registerAdminRoutes(app);
  registerAssetRoutes(app);
  // ... etc
  ```

**Logging in Services:**
- Every service creates its own logger scoped to its name
- Pattern:
  ```typescript
  import { createLogger } from '../lib/logger';
  const log = createLogger('serviceName');
  ```

---

*Convention analysis: 2026-03-16*
