# SamurEye - Adversarial Exposure Validation Platform

## Overview

SamurEye is a comprehensive cybersecurity platform designed for continuous adversarial exposure validation. The application provides automated security assessments through three main journey types: Attack Surface scanning (using nmap and nuclei), Active Directory hygiene analysis, and EDR/AV effectiveness testing. Built as a full-stack web application, it features a modern React frontend with a dark security theme, Express.js backend, and PostgreSQL database with Drizzle ORM for data persistence.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
The client-side is built with **React 18** and **TypeScript**, utilizing modern component patterns and hooks. The UI framework leverages **Radix UI** components with **shadcn/ui** styling for consistent design patterns. **TanStack Query** manages server state and caching, while **Wouter** handles client-side routing. The styling system combines **Tailwind CSS** with CSS custom properties for theming, implementing a dark security-focused color scheme.

### Backend Architecture
The server runs on **Express.js** with TypeScript, following a modular service-oriented architecture. Core services include:
- **Job Queue Service**: Manages asynchronous execution of security journeys
- **Journey Executor Service**: Handles the actual execution logic for different scan types
- **Threat Engine Service**: Processes scan results and generates threat intelligence
- **Encryption Service**: Provides secure credential storage using DEK (Data Encryption Key) methodology

### Authentication & Authorization
The application uses **local authentication** with secure password hashing via **bcrypt** (12 rounds), replacing the previous OIDC integration. Session management is handled through **express-session** with PostgreSQL session storage, including comprehensive security measures:
- **Session fixation protection**: Session IDs are regenerated on login
- **Secure logout**: Complete session destruction and cookie clearing
- **Rate limiting**: Brute force protection with 5 attempts per minute
- **Secure cookies**: httpOnly, sameSite, secure flags for production
- **Production hardening**: SESSION_SECRET requirement and HTTPS enforcement

Role-based access control (RBAC) supports three user roles: global_administrator, operator, and read_only.

### Data Storage
**PostgreSQL** serves as the primary database with **Drizzle ORM** providing type-safe database operations. The schema includes comprehensive tables for users, assets, credentials, journeys, schedules, jobs, threats, and audit logs. Credentials are encrypted at rest using a Key Encryption Key (KEK) and Data Encryption Key (DEK) pattern for enhanced security.

### Real-time Communication
**WebSocket** integration enables real-time updates for job progress, threat notifications, and system status. The frontend maintains persistent connections for live dashboard updates and notification delivery.

### Build System
**Vite** powers the frontend build process with hot module replacement in development. The backend uses **esbuild** for production bundling. The application supports both development and production environments with appropriate optimizations and error handling.

## External Dependencies

### Core Framework Dependencies
- **pg**: Standard PostgreSQL driver for Node.js with connection pooling
- **drizzle-orm**: Type-safe ORM with PostgreSQL adapter
- **express**: Web server framework with middleware support
- **@tanstack/react-query**: Server state management and caching

### UI and Styling
- **@radix-ui/***: Comprehensive set of headless UI components for accessibility
- **tailwindcss**: Utility-first CSS framework
- **class-variance-authority**: Component variant management
- **lucide-react**: Icon library for consistent iconography

### Authentication and Security
- **passport**: Local authentication middleware with strategies
- **bcryptjs**: Secure password hashing and verification (12 rounds)
- **connect-pg-simple**: PostgreSQL session store for persistent sessions
- **express-session**: Session management with security hardening

### Development Tools
- **vite**: Frontend build tool with HMR support
- **@replit/vite-plugin-runtime-error-modal**: Development error overlay
- **@replit/vite-plugin-cartographer**: Replit-specific development enhancements
- **typescript**: Type safety and enhanced developer experience

### Utility Libraries
- **ws**: WebSocket implementation for real-time features
- **memoizee**: Function memoization for performance optimization
- **zod**: Runtime type validation and schema definition
- **date-fns**: Date manipulation and formatting utilities

## Recent Changes

### September 17, 2025
- **Authentication System Hardened**: Replaced OIDC with local authentication using secure password hashing (bcrypt 12 rounds), session fixation protection, and rate limiting (5 attempts/minute)
- **Credentials UI Enhanced**: Fixed empty domain labels in credential selection for EDR/AV journeys; password fields now use type="password" with auto-detection for SSH private keys (displays as multi-line textarea when -----BEGIN detected)
- **Attack Surface Scanning Improved**: Enhanced DNS error handling with 10s timeouts, reduced nmap timeout from 5min to 2min, improved TCP fallback stability (3s per port, max 10 concurrent), and added detailed logging with clear error messages for DNS resolution failures
- **PID Monitoring System Implemented**: Complete process tracking system for nmap/nuclei with real-time WebSocket updates showing PID, process name, and execution stage; cooperative cancellation with multi-phase checks; replaces fixed timeouts with intelligent process monitoring to eliminate false "0 findings" results
- **Nuclei Template Download Fixed**: Corrected ensureNucleiTemplates() function to properly configure environment variables for template downloads, fixing issue where nuclei would run for extended periods but find zero vulnerabilities due to missing templates
- **Bug Fixes**: Resolved job creation/execution issues, corrected URL construction in job results fetching, and fixed 5-minute timeout issues in attack surface scanning caused by DNS resolution failures