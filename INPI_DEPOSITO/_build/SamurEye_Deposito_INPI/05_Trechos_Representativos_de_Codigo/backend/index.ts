// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Bootstrap do servidor Express - ponto de entrada do backend

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

const app = express();

// CORS com credenciais para cookies de sessao
app.use(cors({
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    if (!origin) return callback(null, true);
    if (process.env.NODE_ENV === 'development' && origin.includes('localhost')) {
      return callback(null, true);
    }
    return callback(null, true);
  },
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Middleware de logging para rotas /api
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
      if (logLine.length > 80) logLine = logLine.slice(0, 79) + "...";
      log(logLine);
    }
  });
  next();
});

(async () => {
  // Inicializacao de servicos
  await settingsService.initializeDefaultSettings();
  await storage.initializeDatabaseStructure();
  await threatEngine.startHibernationMonitor();
  schedulerService.start();
  subscriptionService.start();

  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    console.error('Express error handler:', err);
    res.status(status).json({ message });
  });

  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({ port, host: "0.0.0.0", reusePort: true }, () => {
    log(`serving on port ${port}`);
  });

  // Graceful shutdown
  let isShuttingDown = false;
  const shutdown = async (signal: string, isError = false) => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    log(`${signal} received. Shutting down gracefully...`);
    const shutdownTimeout = setTimeout(() => { process.exit(1); }, 10000);
    try {
      await new Promise<void>((resolve) => { server.close(() => resolve()); });
      schedulerService.stop();
      await pool.end();
      clearTimeout(shutdownTimeout);
      process.exit(isError ? 1 : 0);
    } catch (error) {
      clearTimeout(shutdownTimeout);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('uncaughtException', (error) => { shutdown('uncaughtException', true); });
  process.on('unhandledRejection', (reason) => { shutdown('unhandledRejection', true); });
})();
