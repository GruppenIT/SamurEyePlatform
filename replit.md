# SamurEye - Adversarial Exposure Validation Platform

## Overview
SamurEye is a comprehensive cybersecurity platform designed for continuous adversarial exposure validation. It provides automated security assessments through Attack Surface scanning, Active Directory hygiene analysis, and EDR/AV effectiveness testing. The platform is a full-stack web application featuring a React frontend with a dark security theme, an Express.js backend, and a PostgreSQL database. Its core purpose is to identify, track, and reactivate threats across different security journeys, providing real-time vulnerability detection and comprehensive host management.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend
The frontend is built with React 18 and TypeScript, using Radix UI components with shadcn/ui for consistent styling. TanStack Query manages server state, while Wouter handles client-side routing. Styling is done with Tailwind CSS and CSS custom properties for a dark, security-focused theme.

### Backend
The backend runs on Express.js with TypeScript, following a modular service-oriented architecture. Key services include:
- **Job Queue Service**: Manages asynchronous execution of security assessment journeys.
- **Journey Executor Service**: Handles the execution logic for various scan types.
- **Threat Engine Service**: Processes scan results, generates threat intelligence, and supports cross-journey threat reactivation.
- **Encryption Service**: Provides secure credential storage using Data Encryption Key (DEK) methodology.
- **CVE Detection Service**: Integrates with the NIST NVD API for real-time CVE analysis, providing detailed threat entries and remediation guidance.

### Authentication & Authorization
The application uses local authentication with bcrypt for password hashing (12 rounds). Session management is handled by express-session with PostgreSQL storage (connect-pg-simple), featuring comprehensive security controls:

**Session Security System:**
- **Session Versioning**: Global version counter increments on every server restart, immediately invalidating all previous sessions across all devices
- **Active Sessions Tracking**: `active_sessions` table stores metadata (IP, user agent, device info, creation time, last activity) for all authenticated sessions
- **Multi-Device Session Management**: Users can view and revoke individual sessions or all sessions simultaneously via the `/sessions` page
- **Session Revocation**: Immediate invalidation using `sessionStore.destroy()` to purge both database records and in-memory cache; revoked sessions are blocked on next request
- **Middleware Validation**: Every authenticated request validates against `active_sessions` table and session version; fail-secure approach forces logout on validation errors
- **Persistent Rate Limiting**: PostgreSQL-backed `login_attempts` table tracks 5 attempts per email:IP combination with 15-minute lockout; survives server restarts
- **Session Lifecycle**: 8-hour expiration with automatic cleanup, secure HttpOnly cookies, SameSite protection, and automatic HTTPS detection

**RBAC System**: Role-based access control with `global_administrator`, `operator`, and `read_only` roles enforced via middleware.

### Data Storage
PostgreSQL is the primary database, utilizing Drizzle ORM for type-safe operations. The schema includes tables for users, assets, credentials, journeys, schedules, jobs, threats, audit logs, and hosts. Credentials are encrypted at rest using a KEK and DEK pattern.

### Real-time Communication
WebSocket integration provides real-time updates for job progress, threat notifications, and system status, maintaining persistent connections for live dashboard updates.

### Build System
Vite handles the frontend build process, while esbuild bundles the backend for production.

### UI/UX Decisions
The application features a dark security-focused theme. The threat intelligence page includes interactive filtering tiles for severity and status, with dynamic recalculation of stats based on active filters. UI terminology has been updated for clarity (e.g., "Ativos" to "Alvos").

### Technical Implementations
- **Host Management**: Automated host discovery from security scans, intelligent deduplication, and automatic threat-to-host linkage.
- **Threat Lifecycle Management**: Implemented cross-journey threat reactivation and a duplicate prevention system using partial unique indices.
- **Risk Scoring System**: Hosts feature dual-metric risk assessment with historical tracking:
  - **Risk Score (0-100)**: CVSS-based classification with intervals - Critical (90-100), High (70-89), Medium (40-69), Low (10-39), Minimal (0-9)
  - **Raw Score**: Weighted sum of threats using CVSS base values (Critical: 10.0, High: 8.5, Medium: 5.5, Low: 2.5)
  - **Historical Tracking**: `hostRiskHistory` table stores snapshots of risk scores with severity counts and timestamps
  - Automatic snapshot creation when `recalculateHostRiskScore` is called
  - Automatic real-time recalculation when threats are created, updated, or status changes
  - Sortable columns in hosts listing with threat count badges by severity
  - API endpoint `GET /api/hosts/:id/risk-history?limit=30` for retrieving historical risk data
  - Admin endpoint `POST /api/admin/recalculate-risk-scores` for manual backfill/recalculation of all host risk scores
  - **Enhanced Host Details Dialog**: Redesigned with prominent Risk Score display (CVSS color-coded), historical trend chart using recharts, and compact threat badges replacing large summary boxes for cleaner UX
- **Active CVE Validation**: Refactored Attack Surface journey to use active validation with nmap vuln scripts (`--script=vuln`) instead of passive NIST NVD API lookups. CVEs are now validated in real-time against live targets, generating `nmap_vuln` findings with detailed exploit information.
- **Conditional Web Scanning**: Attack Surface journeys feature optional Nuclei web application scanning via the `webScanEnabled` parameter. When enabled, HTTP/HTTPS services are automatically identified and scanned for web vulnerabilities.
- **Three-Phase Attack Surface Scanning**: 
  1. **Discovery Phase**: Port scanning with nmap to identify open ports and services
  2. **Active Validation Phase**: Nmap vuln scripts execution on all discovered ports (always runs)
  3. **Web Scanning Phase**: Nuclei execution on web services (conditional, based on webScanEnabled)
- **OS and Version Detection**: Enhanced nmap usage with `-O` and `--osscan-guess` flags for improved OS detection accuracy, service version normalization, and a robust fallback mechanism for environments without root privileges.
- **Port Sanitization**: Implemented automatic port format normalization to strip `/tcp` and `/udp` suffixes before passing to nmap vuln scripts, ensuring command compatibility.
- **Session Control**: Secure 8-hour session expiration with automatic cleanup and middleware validation.
- **PID Monitoring System**: Real-time process tracking for nmap/nuclei with WebSocket updates and cooperative cancellation.
- **Email Notification System**: Comprehensive notification system with support for three authentication methods:
  - **Basic Password Authentication**: Legacy SMTP password-based authentication (deprecated for Gmail/Microsoft in 2025)
  - **OAuth2 for Google Workspace/Gmail**: Secure OAuth2 authentication with automatic token refresh using googleapis
  - **OAuth2 for Microsoft 365**: Secure OAuth2 authentication with automatic token refresh using @azure/msal-node
  - All OAuth2 credentials (clientId, clientSecret, refreshToken, tenantId) are encrypted using the KEK/DEK pattern
  - Email settings support configurable SMTP hosts, ports, TLS/SSL, and customizable sender information
- **AD Security Journey (Refactored)**: Complete rewrite of Active Directory security assessment using Python WinRM wrapper:
  - **28 PowerShell-Based Tests**: Organized in 6 categories (Configurações Críticas, Gerenciamento de Contas, Kerberos e Delegação, Compartilhamentos e GPOs, Políticas e Configuração, Contas Inativas)
  - **pywinrm Integration**: Uses Python wrapper (`server/utils/winrm-wrapper.py`) with `pywinrm` library for WinRM connectivity, solving PowerShell Core's WSMan limitation on Linux
  - **Python Virtual Environment**: Dedicated virtualenv at `/opt/samureye/venv` with `pywinrm`, `pywinrm[credssp]`, and `requests-ntlm` installed
  - **DC Failover Support**: Primary/secondary domain controller configuration with automatic failover
  - **Category Toggles**: Independent enable/disable for each test category via UI checkboxes
  - **Portuguese Keywords**: Enhanced credential scanning with Portuguese-specific patterns (senha, segredo, credencial)
  - **Finding Types**: Maintains legacy `ad_hygiene` finding type for backward compatibility with existing data
  - **Journey Type**: Renamed from `ad_hygiene` to `ad_security` across schema and UI
  - **EDR/AV Integration**: AD-based workstation discovery intentionally removed; use Network-based mode with specific targets instead
  - **Complete Test Results Tracking**: Comprehensive auditability system that stores ALL test results (pass/fail/error/skipped):
    - `adSecurityTestResults` table stores every test execution with status, evidence, and timestamp
    - All 28 tests are tracked per job execution, including successful tests (not just failures)
    - **Full Execution Evidence**: Every test result includes complete execution details:
      - PowerShell command executed (sanitized with credentials redacted as [REDACTED])
      - stdout output (up to 2000 chars)
      - stderr output (up to 500 chars)
      - exitCode (process exit status)
    - PowerShell commands logged to journalctl for audit trail
    - Test results linked to both jobs and domain hosts for historical audit trail
    - API endpoint `GET /api/hosts/:id/ad-tests` retrieves latest test results for a host
    - **Clickable Evidence Badges**: Host details dialog displays categorized test results with color-coded status badges that open detailed evidence modal when clicked
    - Evidence modal shows: Status, PowerShell command, stdout, stderr, exit code, test ID, and execution timestamp
    - Automatic test count validation ensures all 28 tests are executed and recorded
    - Portuguese category keys used throughout (configuracoes_criticas, gerenciamento_contas, etc.)

## External Dependencies

### Core Frameworks
- **pg**: PostgreSQL driver
- **drizzle-orm**: Type-safe ORM
- **express**: Web server framework
- **@tanstack/react-query**: Server state management

### UI and Styling
- **@radix-ui/***: Headless UI components
- **tailwindcss**: Utility-first CSS framework
- **class-variance-authority**: Component variant management
- **lucide-react**: Icon library

### Authentication and Security
- **passport**: Authentication middleware
- **bcryptjs**: Password hashing
- **connect-pg-simple**: PostgreSQL session store
- **express-session**: Session management

### Utility Libraries
- **ws**: WebSocket implementation
- **memoizee**: Function memoization
- **zod**: Runtime type validation
- **date-fns**: Date manipulation