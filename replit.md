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
The application uses **Replit's OIDC authentication** with session management via **express-session** and PostgreSQL session storage. Role-based access control (RBAC) supports three user roles: global_administrator, operator, and read_only. User sessions are managed with JWT tokens and refresh token rotation for security.

### Data Storage
**PostgreSQL** serves as the primary database with **Drizzle ORM** providing type-safe database operations. The schema includes comprehensive tables for users, assets, credentials, journeys, schedules, jobs, threats, and audit logs. Credentials are encrypted at rest using a Key Encryption Key (KEK) and Data Encryption Key (DEK) pattern for enhanced security.

### Real-time Communication
**WebSocket** integration enables real-time updates for job progress, threat notifications, and system status. The frontend maintains persistent connections for live dashboard updates and notification delivery.

### Build System
**Vite** powers the frontend build process with hot module replacement in development. The backend uses **esbuild** for production bundling. The application supports both development and production environments with appropriate optimizations and error handling.

## External Dependencies

### Core Framework Dependencies
- **@neondatabase/serverless**: PostgreSQL connection pooling and serverless database connectivity
- **drizzle-orm**: Type-safe ORM with PostgreSQL adapter
- **express**: Web server framework with middleware support
- **@tanstack/react-query**: Server state management and caching

### UI and Styling
- **@radix-ui/***: Comprehensive set of headless UI components for accessibility
- **tailwindcss**: Utility-first CSS framework
- **class-variance-authority**: Component variant management
- **lucide-react**: Icon library for consistent iconography

### Authentication and Security
- **openid-client**: OIDC authentication with Replit integration
- **passport**: Authentication middleware
- **bcryptjs**: Password hashing and verification
- **connect-pg-simple**: PostgreSQL session store

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