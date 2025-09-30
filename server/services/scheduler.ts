import { storage } from '../storage';
import { settingsService } from './settingsService';
import { Schedule } from '@shared/schema';

/**
 * Scheduler Service - Responsible for executing scheduled journeys
 * 
 * This service periodically checks active schedules and creates jobs
 * when their execution time arrives.
 */
export class SchedulerService {
  private intervalId: NodeJS.Timeout | null = null;
  private readonly checkIntervalMs = 60000; // Check every minute

  /**
   * Start the scheduler service
   */
  start() {
    console.log('🕐 Iniciando serviço de agendamento...');
    
    // Run immediately on start
    this.checkSchedules();
    
    // Then run every minute
    this.intervalId = setInterval(() => {
      this.checkSchedules();
    }, this.checkIntervalMs);
    
    console.log('✅ Serviço de agendamento iniciado com sucesso');
  }

  /**
   * Stop the scheduler service
   */
  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      console.log('🛑 Serviço de agendamento parado');
    }
  }

  /**
   * Get current date/time in the configured timezone
   */
  private async getCurrentTimeInTimezone(): Promise<{ now: Date; hour: number; minute: number; day: number; date: number }> {
    const timezoneSetting = await storage.getSetting('systemTimezone');
    const timezone = timezoneSetting?.value || 'America/Sao_Paulo';
    const now = new Date();
    
    // Get hour and minute in the configured timezone using formatToParts
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      weekday: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      hour12: false
    });
    
    const parts = formatter.formatToParts(now);
    
    // Map weekday short names to numbers (0=Sunday, 6=Saturday)
    const weekdayMap: Record<string, number> = { 
      'Sun': 0, 'Mon': 1, 'Tue': 2, 'Wed': 3, 'Thu': 4, 'Fri': 5, 'Sat': 6 
    };
    
    const weekdayPart = parts.find(p => p.type === 'weekday')?.value || 'Sun';
    const day = weekdayMap[weekdayPart] || 0;
    const date = parseInt(parts.find(p => p.type === 'day')?.value || '1');
    const hour = parseInt(parts.find(p => p.type === 'hour')?.value || '0');
    const minute = parseInt(parts.find(p => p.type === 'minute')?.value || '0');
    
    return { now, hour, minute, day, date };
  }

  /**
   * Check all active schedules and create jobs if needed
   */
  private async checkSchedules() {
    try {
      const activeSchedules = await storage.getActiveSchedules();
      const timeInfo = await this.getCurrentTimeInTimezone();
      
      for (const schedule of activeSchedules) {
        try {
          await this.processSchedule(schedule, timeInfo.now, timeInfo);
        } catch (error) {
          console.error(`Erro ao processar schedule ${schedule.id}:`, error);
        }
      }
    } catch (error) {
      console.error('Erro ao verificar agendamentos:', error);
    }
  }

  /**
   * Process a single schedule and create a job if it's time
   */
  private async processSchedule(schedule: Schedule, now: Date, timeInfo: { hour: number; minute: number; day: number; date: number }) {
    // Skip on-demand schedules
    if (schedule.kind === 'on_demand') {
      return;
    }

    // Handle one-time schedules
    if (schedule.kind === 'once' && schedule.onceAt) {
      const onceDate = new Date(schedule.onceAt);
      
      // Check if it's time to execute (within the last minute)
      const diffMs = now.getTime() - onceDate.getTime();
      if (diffMs >= 0 && diffMs < this.checkIntervalMs) {
        // Check if already executed
        if (!schedule.lastExecutedAt || new Date(schedule.lastExecutedAt) < onceDate) {
          await this.createJobForSchedule(schedule);
          // Disable schedule after execution
          await storage.updateSchedule(schedule.id, { 
            lastExecutedAt: now,
            enabled: false 
          });
        }
      }
      return;
    }

    // Handle recurring schedules
    if (schedule.kind === 'recurring' && schedule.recurrenceType) {
      const shouldExecute = this.shouldExecuteRecurringSchedule(schedule, now, timeInfo);
      
      if (shouldExecute) {
        // Check if already executed recently (avoid duplicate executions)
        if (schedule.lastExecutedAt) {
          const lastExecution = new Date(schedule.lastExecutedAt);
          const diffMinutes = (now.getTime() - lastExecution.getTime()) / (1000 * 60);
          
          // Don't execute if executed in the last minute
          if (diffMinutes < 1) {
            return;
          }
        }
        
        await this.createJobForSchedule(schedule);
        await storage.updateSchedule(schedule.id, { lastExecutedAt: now });
      }
    }
  }

  /**
   * Determine if a recurring schedule should execute now
   */
  private shouldExecuteRecurringSchedule(schedule: Schedule, now: Date, timeInfo: { hour: number; minute: number; day: number; date: number }): boolean {
    if (!schedule.recurrenceType || schedule.hour === null || schedule.hour === undefined) {
      return false;
    }

    const currentHour = timeInfo.hour;
    const currentMinute = timeInfo.minute;
    const scheduleMinute = schedule.minute || 0;

    // If repeatInterval is set, use interval-based scheduling
    if (schedule.repeatInterval && schedule.repeatUnit) {
      if (!schedule.lastExecutedAt) {
        // First execution: check if current time matches scheduled time
        if (currentHour !== schedule.hour || currentMinute !== scheduleMinute) {
          return false;
        }
        return this.matchesRecurrencePattern(schedule, timeInfo);
      }

      const lastExecution = new Date(schedule.lastExecutedAt);
      const diffMs = now.getTime() - lastExecution.getTime();
      
      let intervalMs = 0;
      if (schedule.repeatUnit === 'hours') {
        intervalMs = schedule.repeatInterval * 60 * 60 * 1000;
      } else if (schedule.repeatUnit === 'days') {
        intervalMs = schedule.repeatInterval * 24 * 60 * 60 * 1000;
      }

      // Execute if interval has passed
      return diffMs >= intervalMs;
    }

    // Standard time-based scheduling
    // Check if we're in the right hour and minute (with 1-minute window)
    if (currentHour !== schedule.hour || currentMinute !== scheduleMinute) {
      return false;
    }

    return this.matchesRecurrencePattern(schedule, timeInfo);
  }

  /**
   * Check if current time matches the recurrence pattern
   */
  private matchesRecurrencePattern(schedule: Schedule, timeInfo: { hour: number; minute: number; day: number; date: number }): boolean {
    switch (schedule.recurrenceType) {
      case 'daily':
        // Execute every day at the specified time
        return true;

      case 'weekly':
        // Execute on the specified day of week
        if (schedule.dayOfWeek !== null && schedule.dayOfWeek !== undefined) {
          return timeInfo.day === schedule.dayOfWeek;
        }
        return false;

      case 'monthly':
        // Execute on the specified day of month
        if (schedule.dayOfMonth !== null && schedule.dayOfMonth !== undefined) {
          return timeInfo.date === schedule.dayOfMonth;
        }
        return false;

      default:
        return false;
    }
  }

  /**
   * Create a job for the given schedule
   */
  private async createJobForSchedule(schedule: Schedule) {
    try {
      const job = await storage.createJob({
        journeyId: schedule.journeyId,
        scheduleId: schedule.id,
        status: 'pending',
        progress: 0,
      });
      
      console.log(`📅 Job criado automaticamente para schedule "${schedule.name}" (Job ID: ${job.id})`);
    } catch (error) {
      console.error(`Erro ao criar job para schedule ${schedule.id}:`, error);
    }
  }
}

// Export singleton instance
export const schedulerService = new SchedulerService();
