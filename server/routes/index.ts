import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "../storage";
import { setupAuth, isAuthenticatedWithPasswordCheck } from "../localAuth";
import { jobQueue } from "../services/jobQueue";
import { APP_VERSION } from "../version";
import { parseCookies, requireActiveSubscription, demoReadOnlyGuard } from "./middleware";
import { registerDashboardRoutes } from "./dashboard";
import { registerReportRoutes } from "./reports";
import { registerAdminRoutes } from "./admin";
import { registerAssetRoutes } from "./assets";
import { registerCredentialRoutes } from "./credentials";
import { registerHostRoutes } from "./hosts";
import { registerJourneyRoutes } from "./journeys";
import { registerScheduleRoutes } from "./schedules";
import { registerJobRoutes } from "./jobs";
import { registerThreatRoutes } from "./threats";
import { registerUserRoutes } from "./users";
import { registerRecommendationRoutes } from "./recommendations";
import { registerEdrDeploymentRoutes } from "./edrDeployments";
import { registerAuthMfaRoutes } from "./auth-mfa";
import { registerAuthPasswordResetRoutes } from "./auth-password-reset";
import { registerActionPlanRoutes } from "./action-plans";
import { registerApiRoutes } from "./apis";
import { registerApiCredentialsRoutes } from "./apiCredentials";
import { registerApiFindingsRoutes } from "./apiFindings";
import { registerGettingStartedRoutes } from "./getting-started";
import { registerDemoRoutes } from "./demo";
import { createLogger } from '../lib/logger';

const log = createLogger('routes');

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Demo read-only enforcement (no-op when DEMO_MODE is not set)
  app.use('/api', demoReadOnlyGuard);

  // Subscription read-only enforcement (global, before all API routes)
  app.use('/api', requireActiveSubscription);

  // WebSocket connections for real-time updates
  const connectedClients = new Set<WebSocket>();

  // Broadcast to all connected clients
  function broadcast(data: any) {
    const message = JSON.stringify(data);
    connectedClients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  // Listen for job updates
  jobQueue.on('jobUpdate', (update) => {
    broadcast({ type: 'jobUpdate', data: update });
  });

  // Auth routes are now handled in localAuth.ts

  // Register all route modules
  registerDashboardRoutes(app);
  registerReportRoutes(app);
  registerAdminRoutes(app);
  registerAssetRoutes(app);
  registerCredentialRoutes(app);
  registerHostRoutes(app);
  registerJourneyRoutes(app);
  registerScheduleRoutes(app);
  registerJobRoutes(app);
  registerThreatRoutes(app);
  registerRecommendationRoutes(app);
  registerUserRoutes(app);
  registerEdrDeploymentRoutes(app);
  registerAuthMfaRoutes(app);
  registerAuthPasswordResetRoutes(app);
  registerActionPlanRoutes(app);
  registerGettingStartedRoutes(app);
  registerDemoRoutes(app);
  registerApiRoutes(app);
  registerApiCredentialsRoutes(app);
  registerApiFindingsRoutes(app);

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: APP_VERSION
    });
  });

  // Phase 15 SAFE-05 — /healthz/api-test-target for dryRun validation.
  // NOT authenticated (infra-only endpoint). Hardcoded response — no DB queries.
  // Path uses /healthz/ prefix (not /api/) so requireActiveSubscription middleware
  // registered at line 37 does NOT intercept. Returns 4 mock findings covering
  // all severities (low/medium/high/critical) with valid owasp_api_category values.
  app.get('/healthz/api-test-target', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      dryRun: true,
      mockFindings: [
        {
          category: 'api9_inventory_2023',
          severity: 'low',
          title: 'Mock: Endpoint sem documentação detectado',
        },
        {
          category: 'api8_misconfiguration_2023',
          severity: 'medium',
          title: 'Mock: CORS permissivo detectado',
        },
        {
          category: 'api2_broken_auth_2023',
          severity: 'high',
          title: 'Mock: JWT alg:none aceito',
        },
        {
          category: 'api1_bola_2023',
          severity: 'critical',
          title: 'Mock: BOLA — acesso cross-identity confirmado',
        },
      ],
    });
  });

  const httpServer = createServer(app);

  // WebSocket server for real-time updates
  const wss = new WebSocketServer({
    server: httpServer,
    path: '/ws',
    verifyClient: async (info, callback) => {
      try {
        // Extract session cookie from upgrade request
        const cookieHeader = info.req.headers.cookie;
        if (!cookieHeader) {
          log.info('websocket rejected: no session cookie');
          callback(false, 401, 'Não autorizado');
          return;
        }

        const cookies = parseCookies(cookieHeader);
        const sessionId = cookies['connect.sid'];
        if (!sessionId) {
          log.info('websocket rejected: missing connect.sid cookie');
          callback(false, 401, 'Não autorizado');
          return;
        }

        // Decode the signed session ID (format: s:<id>.<signature>)
        const rawSid = sessionId.startsWith('s:')
          ? sessionId.slice(2).split('.')[0]
          : sessionId;

        // Verify session exists in active_sessions
        const activeSession = await storage.getActiveSessionBySessionId(rawSid);
        if (!activeSession) {
          log.info('websocket rejected: session not found or revoked');
          callback(false, 401, 'Sessão inválida');
          return;
        }

        callback(true);
      } catch (error) {
        log.error({ err: error }, 'websocket verification error');
        callback(false, 500, 'Erro interno');
      }
    }
  });

  wss.on('connection', (ws) => {
    log.info('websocket client connected (authenticated)');
    connectedClients.add(ws);

    ws.on('close', () => {
      log.info('websocket client disconnected');
      connectedClients.delete(ws);
    });

    ws.on('error', (error) => {
      log.error({ err: error }, 'websocket error');
      connectedClients.delete(ws);
    });

    // Send initial connection confirmation
    ws.send(JSON.stringify({
      type: 'connected',
      message: 'Conectado ao SamurEye'
    }));
  });

  // Export cleanup function for graceful shutdown
  (httpServer as any).closeWebSocket = () => {
    return new Promise<void>((resolve) => {
      // Close all client connections
      wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.close();
        }
      });

      // Close the WebSocket server
      wss.close(() => {
        resolve();
      });
    });
  };

  return httpServer;
}
