// Phase 10 — CRED-01, CRED-05: rota CRUD para api_credentials.
// Mesma rota usada pelo wizard inline-create (Phase 16).
// RBAC: operator + global_administrator (mesmo nivel de POST /api/v1/apis Phase 9).

import type { Express, Request, Response } from "express";
import { z } from "zod";
import { storage } from "../storage";
import {
  insertApiCredentialSchema,
  patchApiCredentialSchema,
  type ApiAuthType,
} from "@shared/schema";
import { isValidUrlPattern } from "../services/credentials/matchUrlPattern";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { createLogger } from "../lib/logger";

const log = createLogger("routes:api-credentials");

export function registerApiCredentialsRoutes(app: Express): void {
  // ── POST /api/v1/api-credentials ─────────────────────────────────────
  app.post(
    "/api/v1/api-credentials",
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: any, res: Response) => {
      // 1. Zod parse
      let body: z.infer<typeof insertApiCredentialSchema>;
      try {
        body = insertApiCredentialSchema.parse(req.body);
      } catch (err: any) {
        log.info({ err: err?.errors }, "api credential rejected by Zod");
        return res
          .status(400)
          .json({ message: "Dados de credencial inválidos", details: err?.errors });
      }

      // 2. Validar urlPattern (whitelist conservadora)
      if (body.urlPattern && !isValidUrlPattern(body.urlPattern)) {
        return res.status(400).json({ message: "URL pattern inválido" });
      }

      // 3. Persistir via storage
      try {
        const cred = await storage.createApiCredential(body, req.user.id);
        log.info(
          { apiCredentialId: cred.id, authType: cred.authType, apiId: cred.apiId },
          "api credential created",
        );
        return res.status(201).json(cred);
      } catch (error: any) {
        if (error?.code === "23505") {
          return res
            .status(409)
            .json({ message: "Credencial já cadastrada com esse nome" });
        }
        log.error({ err: error }, "failed to create api credential");
        return res.status(500).json({ message: "Falha ao processar credencial" });
      }
    },
  );

  // ── GET /api/v1/api-credentials ──────────────────────────────────────
  app.get(
    "/api/v1/api-credentials",
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: Request, res: Response) => {
      const filter: { apiId?: string; authType?: ApiAuthType } = {};
      if (typeof req.query.apiId === "string") filter.apiId = req.query.apiId;
      if (typeof req.query.authType === "string") {
        filter.authType = req.query.authType as ApiAuthType;
      }
      try {
        const list = await storage.listApiCredentials(filter);
        return res.status(200).json(list);
      } catch (error) {
        log.error({ err: error }, "failed to list api credentials");
        return res.status(500).json({ message: "Falha ao listar credenciais" });
      }
    },
  );

  // ── GET /api/v1/api-credentials/:id ──────────────────────────────────
  app.get(
    "/api/v1/api-credentials/:id",
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: Request, res: Response) => {
      try {
        const cred = await storage.getApiCredential(req.params.id);
        if (!cred) {
          return res.status(404).json({ message: "Credencial não encontrada" });
        }
        return res.status(200).json(cred);
      } catch (error) {
        log.error({ err: error }, "failed to get api credential");
        return res.status(500).json({ message: "Falha ao buscar credencial" });
      }
    },
  );

  // ── PATCH /api/v1/api-credentials/:id ────────────────────────────────
  app.patch(
    "/api/v1/api-credentials/:id",
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: any, res: Response) => {
      let patch: z.infer<typeof patchApiCredentialSchema>;
      try {
        patch = patchApiCredentialSchema.parse(req.body);
      } catch (err: any) {
        return res
          .status(400)
          .json({ message: "Dados de credencial inválidos", details: err?.errors });
      }
      if (patch.urlPattern && !isValidUrlPattern(patch.urlPattern)) {
        return res.status(400).json({ message: "URL pattern inválido" });
      }
      try {
        const exists = await storage.getApiCredential(req.params.id);
        if (!exists) {
          return res.status(404).json({ message: "Credencial não encontrada" });
        }
        const updated = await storage.updateApiCredential(
          req.params.id,
          patch,
          req.user.id,
        );
        log.info({ apiCredentialId: req.params.id }, "api credential patched");
        return res.status(200).json(updated);
      } catch (error: any) {
        if (error?.code === "23505") {
          return res
            .status(409)
            .json({ message: "Credencial já cadastrada com esse nome" });
        }
        log.error({ err: error }, "failed to patch api credential");
        return res.status(500).json({ message: "Falha ao processar credencial" });
      }
    },
  );

  // ── DELETE /api/v1/api-credentials/:id ───────────────────────────────
  app.delete(
    "/api/v1/api-credentials/:id",
    isAuthenticatedWithPasswordCheck,
    requireOperator,
    async (req: Request, res: Response) => {
      try {
        const exists = await storage.getApiCredential(req.params.id);
        if (!exists) {
          return res.status(404).json({ message: "Credencial não encontrada" });
        }
        await storage.deleteApiCredential(req.params.id);
        log.info({ apiCredentialId: req.params.id }, "api credential deleted");
        return res.status(204).send();
      } catch (error) {
        log.error({ err: error }, "failed to delete api credential");
        return res.status(500).json({ message: "Falha ao remover credencial" });
      }
    },
  );
}
