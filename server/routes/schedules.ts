import type { Express } from "express";
import { storage } from "../storage";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { requireOperator } from "./middleware";
import { insertScheduleSchema, createScheduleSchema } from "@shared/schema";
import { createLogger } from '../lib/logger';

const log = createLogger('routes:schedules');

export function registerScheduleRoutes(app: Express) {
  app.get('/api/schedules', isAuthenticatedWithPasswordCheck, async (req, res) => {
    try {
      const schedules = await storage.getSchedules();
      res.json(schedules);
    } catch (error) {
      log.error({ err: error }, 'failed to fetch schedules');
      res.status(500).json({ message: "Falha ao buscar agendamentos" });
    }
  });

  app.post('/api/schedules', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const scheduleData = createScheduleSchema.parse(req.body);
      const schedule = await storage.createSchedule(scheduleData, userId);

      await storage.logAudit({
        actorId: userId,
        action: 'create',
        objectType: 'schedule',
        objectId: schedule.id,
        before: null,
        after: schedule,
      });

      res.status(201).json(schedule);
    } catch (error) {
      log.error({ err: error }, 'failed to create schedule');
      res.status(400).json({ message: "Falha ao criar agendamento" });
    }
  });

  app.patch('/api/schedules/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const beforeSchedule = await storage.getSchedule(id);
      if (!beforeSchedule) {
        return res.status(404).json({ message: "Agendamento não encontrado" });
      }

      const updateData = insertScheduleSchema.parse(req.body);
      const schedule = await storage.updateSchedule(id, updateData);

      await storage.logAudit({
        actorId: userId,
        action: 'update',
        objectType: 'schedule',
        objectId: id,
        before: beforeSchedule,
        after: schedule,
      });

      res.json(schedule);
    } catch (error) {
      log.error({ err: error }, 'failed to update schedule');
      res.status(400).json({ message: "Falha ao atualizar agendamento" });
    }
  });

  app.delete('/api/schedules/:id', isAuthenticatedWithPasswordCheck, requireOperator, async (req: any, res) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const beforeSchedule = await storage.getSchedule(id);

      await storage.deleteSchedule(id);

      await storage.logAudit({
        actorId: userId,
        action: 'delete',
        objectType: 'schedule',
        objectId: id,
        before: beforeSchedule || null,
        after: null,
      });

      res.status(204).send();
    } catch (error) {
      log.error({ err: error }, 'failed to delete schedule');
      res.status(400).json({ message: "Falha ao excluir agendamento" });
    }
  });
}
