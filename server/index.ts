import express, { type Request, Response, NextFunction } from "express";
import cors from "cors";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { pool } from "./db";
import { settingsService } from "./services/settingsService";
import { threatEngine } from "./services/threatEngine";
import { schedulerService } from "./services/scheduler";
import { subscriptionService } from "./services/subscriptionService";
import { storage } from "./storage";
import { createLogger } from './lib/logger';

const slog = createLogger('server');

const app = express();

// FND-003: CORS configurável — rejeita origens desconhecidas por padrão.
// Configure via ALLOWED_ORIGINS env var (comma-separated).
// Example: ALLOWED_ORIGINS=https://console.samureye.com.br,https://192.168.1.100:5000
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    // Requests with no Origin header: same-origin, curl, mobile apps — always allow
    if (!origin) return callback(null, true);

    // Development: allow any localhost origin
    if (process.env.NODE_ENV !== 'production' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
      return callback(null, true);
    }

    // Explicitly allowed origins from ALLOWED_ORIGINS env var
    if (allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Appliance UI: the browser accesses the same host, so Origin matches the server.
    // Allow when no ALLOWED_ORIGINS is set (appliance default — single-host deployment).
    if (allowedOrigins.length === 0) {
      return callback(null, true);
    }

    // Reject unrecognized origins
    slog.warn({ origin }, 'CORS rejected origin');
    return callback(new Error('Origem não permitida pela política de CORS'));
  },
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Inicializar configurações padrão do sistema
  slog.info('initializing default system settings');
  await settingsService.initializeDefaultSettings();
  slog.info('default settings initialized');
  
  // Initialize database structure (unique indexes, duplicate consolidation)
  await storage.initializeDatabaseStructure();
  
  // Start hibernation monitor for automatic threat reactivation
  slog.info('starting hibernated threat monitor');
  await threatEngine.startHibernationMonitor();
  
  // Start scheduler service for automatic job execution
  schedulerService.start();

  // Start subscription service (heartbeat to central console)
  subscriptionService.start();
  
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    slog.error({ err }, 'express error handler');
    res.status(status).json({ message });
    // Don't throw after responding - this would trigger process termination
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });

  // Graceful shutdown handlers
  let isShuttingDown = false;
  const shutdown = async (signal: string, isError = false) => {
    if (isShuttingDown) return;
    isShuttingDown = true;

    log(`${signal} received. Shutting down gracefully...`);
    
    // Set a shutdown timeout
    const shutdownTimeout = setTimeout(() => {
      log('Forced shutdown after timeout');
      process.exit(1);
    }, 10000); // 10 seconds timeout

    try {
      // Stop accepting new connections and await completion
      await new Promise<void>((resolve) => {
        server.close(() => {
          log('HTTP server stopped accepting new connections');
          resolve();
        });
      });

      // Close WebSocket connections if available
      if (typeof (server as any).closeWebSocket === 'function') {
        await (server as any).closeWebSocket();
        log('WebSocket server closed');
      }

      // Stop scheduler service
      schedulerService.stop();
      log('Scheduler service stopped');

      // Close database pool
      await pool.end();
      log('PostgreSQL pool closed');
      
      clearTimeout(shutdownTimeout);
      log('Shutdown completed successfully');
      process.exit(isError ? 1 : 0);
    } catch (error) {
      clearTimeout(shutdownTimeout);
      log(`Error during shutdown: ${error}`);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('uncaughtException', (error) => {
    log(`Uncaught exception: ${error}`);
    shutdown('uncaughtException', true);
  });
  process.on('unhandledRejection', (reason) => {
    log(`Unhandled rejection: ${reason}`);
    shutdown('unhandledRejection', true);
  });
})();
