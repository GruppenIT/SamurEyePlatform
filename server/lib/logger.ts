import pino from 'pino';

// ---------------------------------------------------------------------------
// FND-008: Structured logging with automatic credential redaction
// ---------------------------------------------------------------------------
//
// Usage:
//   import { createLogger } from '../lib/logger';
//   const log = createLogger('componentName');
//   log.info('message');
//   log.info({ host, duration }, 'scan complete');
//   log.error({ err }, 'operation failed');
//
// Environment variables:
//   LOG_LEVEL  — debug | info | warn | error | fatal  (default: info)
//   NODE_ENV   — "development" enables pretty-printing to stdout
// ---------------------------------------------------------------------------

const isDev = process.env.NODE_ENV === 'development';

/**
 * Paths whose values are replaced with "[REDACTED]" in every log entry.
 * Uses pino's built-in redaction (zero-copy, no perf hit on hot path).
 * Covers nested objects and arrays automatically.
 */
const REDACT_PATHS = [
  // Direct fields
  'password',
  'secret',
  'token',
  'apiKey',
  'api_key',
  'secretEncrypted',
  'dekEncrypted',
  'sessionSecret',
  'encryptionKey',
  'cookie',
  'authorization',

  // Nested under common parent objects
  'credential.password',
  'credential.secret',
  'credential.token',
  'credentials.password',
  'credentials.secret',
  'credentials.token',
  'headers.authorization',
  'headers.cookie',

  // Wildcard nested — catches arrays of credentials, etc.
  '*.password',
  '*.secret',
  '*.token',
  '*.apiKey',
  '*.secretEncrypted',
  '*.dekEncrypted',
];

/**
 * Root pino instance. All child loggers inherit redaction & transport config.
 */
const rootLogger = pino({
  level: process.env.LOG_LEVEL || 'info',

  // Structured redaction — pino replaces matching paths before serialization
  redact: {
    paths: REDACT_PATHS,
    censor: '[REDACTED]',
  },

  // Timestamp as ISO string for human-readability in log aggregators
  timestamp: pino.stdTimeFunctions.isoTime,

  // Base bindings present on every log line
  base: {
    service: 'samureye',
    pid: process.pid,
  },

  // In development, pipe through pino-pretty for readable console output.
  // In production, emit newline-delimited JSON (compatible with ELK, Loki, etc.)
  ...(isDev
    ? {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss.l',
            ignore: 'pid,hostname,service',
            singleLine: false,
          },
        },
      }
    : {}),
});

/**
 * Create a child logger scoped to a specific component/module.
 *
 * @param component - Short name identifying the module (e.g. 'edrScanner', 'routes', 'storage')
 * @returns A pino child logger with the component name baked into every log line
 *
 * @example
 * const log = createLogger('subscriptionService');
 * log.info({ url }, 'heartbeat sent');
 * log.warn({ statusCode }, 'unexpected response');
 * log.error({ err }, 'heartbeat failed');
 */
export function createLogger(component: string): pino.Logger {
  return rootLogger.child({ component });
}

/**
 * The root logger instance — use only in index.ts / top-level bootstrap.
 * Prefer createLogger('name') for all other modules.
 */
export default rootLogger;
