# Technology Stack

**Analysis Date:** 2025-03-16

## Languages

**Primary:**
- TypeScript 5.6.3 - Full stack (client, server, shared)
- JavaScript/Node.js - Runtime for server and build tools

**Secondary:**
- Bash/Shell - Build scripts and utilities

## Runtime

**Environment:**
- Node.js 20.16.11 (per package.json types)

**Package Manager:**
- npm (via package-lock.json)
- Lockfile: Present (`package-lock.json`)

## Frameworks

**Core:**
- Express.js 4.21.2 - REST API and server framework
- React 18.3.1 - Client UI framework
- Vite 6.4.1 - Build tool and dev server

**Database:**
- Drizzle ORM 0.39.1 - SQL query builder and schema management
- PostgreSQL (via `pg` 8.16.3) - Primary database

**Authentication & Session:**
- Passport.js 0.7.0 - Authentication middleware
- passport-local 1.0.0 - Local strategy for username/password
- openid-client 6.7.1 - OpenID Connect client (Replit Auth)
- express-session 1.18.2 - Session management
- connect-pg-simple 10.0.0 - PostgreSQL session store

**UI Components:**
- Radix UI - Headless component library (20+ packages)
- Tailwind CSS 3.4.17 - Utility-first CSS framework
- Framer Motion 11.13.1 - Animation library

**Testing:**
- Vitest 4.0.18 - Unit/integration testing framework
- No E2E test framework detected

**Build & Development:**
- esbuild 0.25.0 - Fast bundler for server
- Vite plugins (cartographer, runtime-error-modal)
- TypeScript compiler (tsx) - TS-Node replacement

## Key Dependencies

**Critical:**
- bcryptjs 3.0.2 - Password hashing for local auth
- zod 3.24.2 - Schema validation for API/forms
- drizzle-zod 0.7.0 - Automatic Zod schema generation from DB schema

**Infrastructure:**
- pino 10.3.1 - Structured JSON logging (production-grade)
- pino-pretty 13.1.3 - Pretty-printed logs for development

**API & HTTP:**
- googleapis 161.0.0 - Google APIs for OAuth2 Gmail integration
- @azure/msal-node 3.8.0 - Azure AD / Microsoft OAuth2 integration
- ssh2 1.17.0 - SSH client for remote command execution and WMI collection
- ldapts 8.0.9 - LDAP/Active Directory client for AD security scanning
- nodemailer 7.0.6 - Email sending (SMTP, OAuth2)

**Client Libraries:**
- @tanstack/react-query 5.60.5 - Data fetching and caching
- wouter 3.3.5 - Lightweight client-side routing
- react-hook-form 7.55.0 - Form state management
- react-icons 5.4.0 - Icon library

**Utilities:**
- nanoid 5.1.5 - Unique ID generation
- date-fns 3.6.0 - Date/time utilities
- recharts 2.15.2 - React charting library

**Networking:**
- ws 8.18.3 - WebSocket support
- cors 2.8.5 - Cross-Origin Resource Sharing middleware

## Configuration

**Environment:**
- Via environment variables (`.env` not present in repo):
  - `DATABASE_URL` - PostgreSQL connection string (required)
  - `NODE_ENV` - Development or production
  - `PORT` - Server port (default: 5000)
  - `ALLOWED_ORIGINS` - Comma-separated CORS origins
- Configuration files:
  - `drizzle.config.ts` - Drizzle ORM migration config
  - `tsconfig.json` - TypeScript compiler options with path aliases

**Build:**
- `package.json` scripts
- Vite config (inferred from dependencies)
- Drizzle migrations directory: `./migrations/`

**Path Aliases (tsconfig.json):**
- `@/*` → `./client/src/*` - Client components and pages
- `@shared/*` → `./shared/*` - Shared types and schemas

## Platform Requirements

**Development:**
- Node.js 20+
- npm
- PostgreSQL database
- TypeScript knowledge

**Production:**
- Node.js 20+ runtime
- PostgreSQL 12+ database
- Environment variables for secrets (DATABASE_URL, API keys for Gmail/Azure)
- HTTPS reverse proxy recommended (appliance serves on single port)

**Deployment:**
- Single deployable artifact: `dist/index.js` (built via esbuild)
- Client assets: Pre-built from Vite
- Runs on appliance at `0.0.0.0:5000` (default)

---

*Stack analysis: 2025-03-16*
