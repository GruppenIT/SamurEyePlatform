import type { Express, Request } from "express";
import { storage } from "../storage";
import { db } from "../db";
import {
  journeys,
  users,
  notificationPolicies,
  actionPlans,
} from "@shared/schema";
import { count } from "drizzle-orm";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireAdmin } from "./middleware";
import { createLogger } from "../lib/logger";

const log = createLogger("routes:getting-started");

interface AuthenticatedRequest extends Request {
  user: { id: string };
}

interface SkipEntry {
  at: string;
  reason: string;
}

const STEP_IDS = [
  "appliance_config",
  "mensageria",
  "first_user",
  "journey_attack_surface",
  "journey_ad_security",
  "journey_edr_av",
  "journey_web_application",
  "journey_api_security",
  "notification_policy",
  "action_plan",
] as const;

type StepId = (typeof STEP_IDS)[number];

const SKIPPABLE = new Set<StepId>([
  "journey_attack_surface",
  "journey_ad_security",
  "journey_edr_av",
  "journey_web_application",
  "journey_api_security",
  "notification_policy",
]);

interface StepStatus {
  id: StepId;
  completed: boolean;
  skippable: boolean;
  skipped: boolean;
  skipReason: string | null;
  skippedAt: string | null;
}

async function computeCompletion(): Promise<Record<StepId, boolean>> {
  const [allSettings, emailSettings, allUsers, journeyRows, policyCount, planCount] =
    await Promise.all([
      storage.getAllSettings(),
      storage.getEmailSettings(),
      storage.getAllUsers(),
      db.select({ type: journeys.type }).from(journeys),
      db.select({ count: count() }).from(notificationPolicies),
      db.select({ count: count() }).from(actionPlans),
    ]);

  const settingsMap = Object.fromEntries(allSettings.map((s) => [s.key, s.value]));
  const journeyTypes = new Set(journeyRows.map((j) => j.type));

  return {
    appliance_config:
      Boolean(settingsMap["applianceName"]) && Boolean(settingsMap["locationType"]),
    mensageria: Boolean(emailSettings?.smtpHost),
    first_user: allUsers.some((u) => u.role !== "global_administrator"),
    journey_attack_surface: journeyTypes.has("attack_surface"),
    journey_ad_security: journeyTypes.has("ad_security"),
    journey_edr_av: journeyTypes.has("edr_av"),
    journey_web_application: journeyTypes.has("web_application"),
    journey_api_security: journeyTypes.has("api_security"),
    notification_policy: Number(policyCount[0].count) > 0,
    action_plan: Number(planCount[0].count) > 0,
  };
}

export function registerGettingStartedRoutes(app: Express) {
  app.get(
    "/api/getting-started/status",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (_req, res) => {
      try {
        const [completion, skippedSetting, dismissedSetting] = await Promise.all([
          computeCompletion(),
          storage.getSetting("gettingStarted.skipped"),
          storage.getSetting("gettingStarted.dismissed"),
        ]);

        const rawSkipped = skippedSetting?.value;
        const skipped = (
          rawSkipped && typeof rawSkipped === "object" && !Array.isArray(rawSkipped)
            ? rawSkipped
            : {}
        ) as Record<string, SkipEntry>;
        const dismissed = Boolean(dismissedSetting?.value);

        const steps: StepStatus[] = STEP_IDS.map((id) => {
          const entry = skipped[id];
          return {
            id,
            completed: completion[id],
            skippable: SKIPPABLE.has(id),
            skipped: Boolean(entry),
            skipReason: entry?.reason || null,
            skippedAt: entry?.at || null,
          };
        });

        const completedCount = steps.filter((s) => s.completed).length;
        const skippedCount = steps.filter((s) => !s.completed && s.skipped).length;

        res.json({
          steps,
          totalSteps: STEP_IDS.length,
          completedCount,
          skippedCount,
          dismissed,
        });
      } catch (error) {
        log.error({ err: error }, "failed to fetch getting-started status");
        res.status(500).json({ message: "Falha ao buscar status do guia inicial" });
      }
    }
  );

  app.post(
    "/api/getting-started/skip",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req, res) => {
      try {
        const { stepId, reason = "" } = req.body ?? {};
        if (!(STEP_IDS as readonly string[]).includes(stepId)) {
          return res.status(400).json({ message: "Step ID inválido" });
        }
        if (!SKIPPABLE.has(stepId as StepId)) {
          return res.status(400).json({ message: "Esta etapa não pode ser ignorada" });
        }
        // Read-modify-write: low-concurrency admin path, no lock needed
        const existing = await storage.getSetting("gettingStarted.skipped");
        const rawExisting = existing?.value;
        const map = (
          rawExisting && typeof rawExisting === "object" && !Array.isArray(rawExisting)
            ? rawExisting
            : {}
        ) as Record<string, SkipEntry>;
        map[stepId] = { at: new Date().toISOString(), reason: String(reason) };
        await storage.setSetting("gettingStarted.skipped", map, (req as AuthenticatedRequest).user.id);
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to skip step");
        res.status(500).json({ message: "Falha ao ignorar etapa" });
      }
    }
  );

  app.delete(
    "/api/getting-started/skip/:stepId",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req, res) => {
      try {
        const { stepId } = req.params;
        if (!(STEP_IDS as readonly string[]).includes(stepId)) {
          return res.status(400).json({ message: "Step ID inválido" });
        }
        // Read-modify-write: low-concurrency admin path, no lock needed
        const existing = await storage.getSetting("gettingStarted.skipped");
        const rawExisting = existing?.value;
        const map = (
          rawExisting && typeof rawExisting === "object" && !Array.isArray(rawExisting)
            ? rawExisting
            : {}
        ) as Record<string, SkipEntry>;
        delete map[stepId];
        await storage.setSetting("gettingStarted.skipped", map, (req as AuthenticatedRequest).user.id);
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to unskip step");
        res.status(500).json({ message: "Falha ao retomar etapa" });
      }
    }
  );

  app.post(
    "/api/getting-started/dismiss",
    isAuthenticatedWithPasswordCheck,
    requireAdmin,
    async (req, res) => {
      try {
        const [completion, skippedSetting] = await Promise.all([
          computeCompletion(),
          storage.getSetting("gettingStarted.skipped"),
        ]);
        const rawSkipped = skippedSetting?.value;
        const skipped = (
          rawSkipped && typeof rawSkipped === "object" && !Array.isArray(rawSkipped)
            ? rawSkipped
            : {}
        ) as Record<string, SkipEntry>;
        const allDone = STEP_IDS.every((id) => completion[id] || Boolean(skipped[id]));
        if (!allDone) {
          return res
            .status(400)
            .json({ message: "Há etapas pendentes — conclua ou ignore-as antes de fechar" });
        }
        await storage.setSetting(
          "gettingStarted.dismissed",
          { at: new Date().toISOString() },
          (req as AuthenticatedRequest).user.id
        );
        res.json({ ok: true });
      } catch (error) {
        log.error({ err: error }, "failed to dismiss getting-started");
        res.status(500).json({ message: "Falha ao fechar guia" });
      }
    }
  );
}
