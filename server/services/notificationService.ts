import { emailService } from './emailService';
import { storage } from '../storage';
import type { Threat, User, NotificationPolicy, EmailSettings } from '@shared/schema';

export class NotificationService {
  async notifyThreatCreated(threat: Threat): Promise<void> {
    try {
      const policies = await this.findMatchingPolicies(threat, 'open');
      
      if (policies.length === 0) {
        console.log(`Nenhuma política de notificação corresponde à ameaça ${threat.id}`);
        return;
      }

      const emailSettings = await storage.getEmailSettings();
      if (!emailSettings) {
        console.log('Configurações de e-mail não definidas, notificações não serão enviadas');
        return;
      }

      const html = emailService.generateThreatEmailHtml(
        {
          ...threat,
          description: threat.description || undefined,
        },
        'created'
      );

      for (const policy of policies) {
        await this.sendNotification(
          emailSettings,
          policy,
          threat,
          'Nova Ameaça Detectada',
          html
        );
      }
    } catch (error) {
      console.error('Erro ao enviar notificações de nova ameaça:', error);
    }
  }

  async notifyThreatStatusChanged(
    threat: Threat,
    oldStatus: string,
    newStatus: string,
    user: User,
    justification: string
  ): Promise<void> {
    try {
      const policies = await this.findMatchingPolicies(threat, newStatus);
      
      if (policies.length === 0) {
        console.log(`Nenhuma política de notificação corresponde à mudança de status da ameaça ${threat.id}`);
        return;
      }

      const emailSettings = await storage.getEmailSettings();
      if (!emailSettings) {
        console.log('Configurações de e-mail não definidas, notificações não serão enviadas');
        return;
      }

      const html = emailService.generateThreatEmailHtml(
        {
          ...threat,
          description: threat.description || undefined,
        },
        'status_changed',
        {
          user,
          oldStatus,
          newStatus,
          justification,
        }
      );

      const subject = `Status de Ameaça Alterado: ${threat.title}`;

      for (const policy of policies) {
        await this.sendNotification(
          emailSettings,
          policy,
          threat,
          subject,
          html
        );
      }
    } catch (error) {
      console.error('Erro ao enviar notificações de mudança de status:', error);
    }
  }

  private async findMatchingPolicies(
    threat: Threat,
    status: string
  ): Promise<NotificationPolicy[]> {
    const allPolicies = await storage.getNotificationPolicies();
    
    return allPolicies.filter(policy => {
      if (!policy.enabled) {
        return false;
      }

      const matchesSeverity = policy.severities.includes(threat.severity);
      const matchesStatus = policy.statuses.includes(status);

      return matchesSeverity && matchesStatus;
    });
  }

  private async sendNotification(
    emailSettings: EmailSettings,
    policy: NotificationPolicy,
    threat: Threat,
    subject: string,
    html: string
  ): Promise<void> {
    try {
      await emailService.sendEmail(emailSettings, {
        to: policy.emailAddresses,
        subject: `[SamurEye] ${subject}`,
        html,
      });

      await storage.createNotificationLog({
        policyId: policy.id,
        threatId: threat.id,
        emailAddresses: policy.emailAddresses,
        subject,
        body: html,
        status: 'sent',
      });

      console.log(`Notificação enviada com sucesso para política ${policy.name}`);
    } catch (error) {
      console.error(`Erro ao enviar notificação para política ${policy.name}:`, error);

      await storage.createNotificationLog({
        policyId: policy.id,
        threatId: threat.id,
        emailAddresses: policy.emailAddresses,
        subject,
        body: html,
        status: 'failed',
        error: error instanceof Error ? error.message : 'Erro desconhecido',
      });
    }
  }
}

export const notificationService = new NotificationService();
