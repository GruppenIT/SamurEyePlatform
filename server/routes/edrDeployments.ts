import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:edrDeployments');

export function registerEdrDeploymentRoutes(app: Express) {
  app.get('/api/edr-deployments', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const { journeyId } = req.query;
      if (!journeyId || typeof journeyId !== 'string') {
        return res.status(400).json({ message: "journeyId é obrigatório" });
      }
      const deployments = await storage.getEdrDeploymentsByJourneyWithHost(journeyId);
      res.json(deployments);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch edr deployments');
      res.status(500).json({ message: "Falha ao buscar implantações EDR" });
    }
  });
}
