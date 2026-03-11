import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator, patchJourneySchema, journeyCredentialInputSchema } from "./middleware";
import { insertJourneySchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:journeys');

export function registerJourneyRoutes(app: Express) {
  app.get('/api/journeys', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const journeys = await storage.getJourneys();
      res.json(journeys);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch journeys');
      res.status(500).json({ message: "Falha ao buscar jornadas" });
    }
  });

  app.post('/api/journeys', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const journeyData = insertJourneySchema.parse(req.body);

      // Server-side validation: ensure at least one target or TAG is selected
      if (journeyData.type === 'attack_surface' ||
          (journeyData.type === 'edr_av' && (journeyData.params as any)?.edrAvType === 'network_based')) {
        const mode = journeyData.targetSelectionMode || 'individual';
        const hasAssets = Array.isArray(journeyData.params?.assetIds) && journeyData.params.assetIds.length > 0;
        const hasTags = Array.isArray(journeyData.selectedTags) && journeyData.selectedTags.length > 0;

        if (mode === 'individual' && !hasAssets) {
          return res.status(400).json({
            message: "Pelo menos um alvo deve ser selecionado no modo Individual"
          });
        }
        if (mode === 'by_tag' && !hasTags) {
          return res.status(400).json({
            message: "Pelo menos uma TAG deve ser selecionada no modo Tag-Based"
          });
        }
      }

      const journey = await storage.createJourney(journeyData, userId);

      // Handle journey credentials (if provided)
      const credentials = req.body.credentials;

      if (Array.isArray(credentials) && credentials.length > 0) {
        for (const cred of credentials) {
          // Validate each credential entry
          const validCred = journeyCredentialInputSchema.parse(cred);
          await storage.createJourneyCredential({
            journeyId: journey.id,
            credentialId: validCred.credentialId,
            protocol: validCred.protocol,
            priority: validCred.priority,
          });
        }
      }

      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'journey',
        objectId: journey.id,
        before: null,
        after: journey,
      });

      res.status(201).json(journey);
    } catch (error) {
      log.error({ err: error }, 'failed to create journey');
      res.status(400).json({ message: "Falha ao criar jornada" });
    }
  });

  app.patch('/api/journeys/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields
      const updates = patchJourneySchema.parse(req.body);

      const beforeJourney = await storage.getJourney(id);
      if (!beforeJourney) {
        return res.status(404).json({ message: "Jornada não encontrada" });
      }
      const { credentials, ...journeyUpdates } = updates;
      const journey = await storage.updateJourney(id, journeyUpdates as any);

      // Handle journey credentials update (if provided in validated data)
      if (Array.isArray(credentials)) {
        // Delete all existing credentials for this journey
        await storage.deleteJourneyCredentials(id);

        // Create new credentials with validation
        if (credentials.length > 0) {
          for (const cred of credentials) {
            const validCred = journeyCredentialInputSchema.parse(cred);
            await storage.createJourneyCredential({
              journeyId: id,
              credentialId: validCred.credentialId,
              protocol: validCred.protocol,
              priority: validCred.priority,
            });
          }
        }
      }

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'journey',
        objectId: id,
        before: beforeJourney || null,
        after: journey,
      });

      res.json(journey);
    } catch (error) {
      log.error({ err: error }, 'failed to update journey');
      res.status(400).json({ message: "Falha ao atualizar jornada" });
    }
  });

  app.delete('/api/journeys/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const beforeJourney = await storage.getJourney(id);
      await storage.deleteJourney(id);

      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'journey',
        objectId: id,
        before: beforeJourney || null,
        after: null,
      });

      res.status(204).send();
    } catch (error) {
      log.error({ err: error }, 'failed to delete journey');
      res.status(400).json({ message: "Falha ao excluir jornada" });
    }
  });

  // Get credentials for a specific journey
  app.get('/api/journeys/:id/credentials', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { id } = req.params;
      const credentials = await storage.getJourneyCredentials(id);
      res.json(credentials);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch journey credentials');
      res.status(500).json({ message: "Falha ao buscar credenciais da jornada" });
    }
  });
}
