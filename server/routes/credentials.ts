import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator, patchCredentialSchema } from "./middleware";
import { insertCredentialSchema } from "@shared/schema";
import { encryptionService } from "../services/encryption";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:credentials');

export function registerCredentialRoutes(app: Express) {
  app.get('/api/credentials', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const credentials = await storage.getCredentials();
      // Note: storage.getCredentials() already omits secretEncrypted/dekEncrypted
      res.json(credentials);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch credentials');
      res.status(500).json({ message: "Falha ao buscar credenciais" });
    }
  });

  app.post('/api/credentials', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const credentialData = insertCredentialSchema.parse(req.body);

      // Encrypt the secret
      const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(credentialData.secret);

      const credential = await storage.createCredential({
        name: credentialData.name,
        type: credentialData.type,
        hostOverride: credentialData.hostOverride ?? null,
        port: credentialData.port ?? null,
        domain: credentialData.domain ?? null,
        username: credentialData.username,
        secretEncrypted,
        dekEncrypted,
        createdBy: userId,
      }, userId);

      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'credential',
        objectId: credential.id,
        before: null,
        after: { ...credential, secretEncrypted: '[ENCRYPTED]', dekEncrypted: '[ENCRYPTED]' },
      });

      res.status(201).json({
        ...credential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      });
    } catch (error) {
      log.error({ err: error }, 'failed to create credential');
      res.status(400).json({ message: "Falha ao criar credencial" });
    }
  });

  app.patch('/api/credentials/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Validate allowed fields
      const updateData = patchCredentialSchema.parse(req.body);

      const existingCredential = await storage.getCredential(id);
      if (!existingCredential) {
        return res.status(404).json({ message: "Credencial não encontrada" });
      }

      const beforeState = {
        ...existingCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      };

      const updatePayload: any = {
        name: updateData.name,
        type: updateData.type,
        hostOverride: updateData.hostOverride ?? null,
        port: updateData.port ?? null,
        domain: updateData.domain ?? null,
        username: updateData.username,
      };

      if (updateData.secret && updateData.secret.trim() !== '') {
        const { secretEncrypted, dekEncrypted } = encryptionService.encryptCredential(updateData.secret);
        updatePayload.secretEncrypted = secretEncrypted;
        updatePayload.dekEncrypted = dekEncrypted;
      }

      const updatedCredential = await storage.updateCredential(id, updatePayload);

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'credential',
        objectId: id,
        before: beforeState,
        after: { ...updatedCredential, secretEncrypted: '[ENCRYPTED]', dekEncrypted: '[ENCRYPTED]' },
      });

      res.json({
        ...updatedCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      });
    } catch (error) {
      log.error({ err: error }, 'failed to update credential');
      res.status(400).json({ message: "Falha ao atualizar credencial" });
    }
  });

  app.delete('/api/credentials/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      // Capture before state for audit (with redacted secrets)
      const existingCredential = await storage.getCredential(id);
      if (!existingCredential) {
        return res.status(404).json({ message: "Credencial não encontrada" });
      }
      const beforeState = {
        ...existingCredential,
        secretEncrypted: '[ENCRYPTED]',
        dekEncrypted: '[ENCRYPTED]',
      };

      await storage.deleteCredential(id);

      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'credential',
        objectId: id,
        before: beforeState,
        after: null,
      });

      res.status(204).send();
    } catch (error) {
      log.error({ err: error }, 'failed to delete credential');
      res.status(400).json({ message: "Falha ao excluir credencial" });
    }
  });
}
