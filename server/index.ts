import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { pool } from "./db";

const app = express();
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
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    console.error('Express error handler:', err);
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
