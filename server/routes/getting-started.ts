// server/routes/getting-started.ts
import type { Express } from "express";
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
    async (req: any, res) => {
      try {
        const [completion, skippedSetting, dismissedSetting] = await Promise.all([
          computeCompletion(),
          storage.getSetting("gettingStarted.skipped"),
          storage.getSetting("gettingStarted.dismissed"),
        ]);

        const skipped = (skippedSetting?.value ?? {}) as Record<
          string,
          { at: string; reason: string }
        >;
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
}
