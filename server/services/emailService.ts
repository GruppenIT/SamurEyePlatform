import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { EmailSettings } from '@shared/schema';
import { EncryptionService } from './encryption';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}

export class EmailService {
  private encryptionService: EncryptionService;

  constructor() {
    this.encryptionService = new EncryptionService();
  }

  async createTransporter(settings: EmailSettings): Promise<Transporter> {
    if (!settings.authPassword || !settings.dekEncrypted) {
      throw new Error('Credenciais de e-mail não configuradas corretamente');
    }

    const password = this.encryptionService.decryptCredential(
      settings.authPassword,
      settings.dekEncrypted
    );

    const config: any = {
      host: settings.smtpHost,
      port: settings.smtpPort,
      secure: settings.smtpSecure,
      auth: {
        user: settings.authUser,
        pass: password,
      },
    };

    if (!settings.smtpSecure && settings.smtpPort === 587) {
      config.requireTLS = true;
      config.tls = {
        servername: settings.smtpHost,
      };
    }

    return nodemailer.createTransport(config);
  }

  async sendEmail(settings: EmailSettings, options: EmailOptions): Promise<void> {
    try {
      const transporter = await this.createTransporter(settings);

      const mailOptions = {
        from: `"${settings.fromName}" <${settings.fromEmail}>`,
        to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
        subject: options.subject,
        html: options.html,
        text: options.text || this.htmlToText(options.html),
      };

      await transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Erro ao enviar e-mail:', error);
      throw new Error(`Falha ao enviar e-mail: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  async testConnection(settings: EmailSettings): Promise<boolean> {
    try {
      const transporter = await this.createTransporter(settings);
      
      // Add timeout to prevent hanging
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timeout: Servidor SMTP não respondeu em 15 segundos')), 15000);
      });
      
      await Promise.race([
        transporter.verify(),
        timeoutPromise
      ]);
      
      return true;
    } catch (error) {
      console.error('Erro ao testar conexão SMTP:', error);
      throw new Error(`Falha ao conectar ao servidor SMTP: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  private htmlToText(html: string): string {
    return html
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>/gi, '\n\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .trim();
  }

  generateThreatEmailHtml(
    threat: {
      id: string;
      title: string;
      description?: string;
      severity: string;
      status: string;
      evidence?: Record<string, any>;
    },
    action: 'created' | 'status_changed',
    details?: {
      user?: { firstName: string; lastName: string };
      oldStatus?: string;
      newStatus?: string;
      justification?: string;
    }
  ): string {
    const severityColors: Record<string, string> = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#3b82f6',
    };

    const severityColor = severityColors[threat.severity] || '#6b7280';

    const baseUrl = process.env.REPLIT_DOMAINS?.split(',')[0] || 'localhost:5000';
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const threatUrl = `${protocol}://${baseUrl}/threats/${threat.id}`;

    let actionTitle = '';
    let actionDescription = '';

    if (action === 'created') {
      actionTitle = '🚨 Nova Ameaça Detectada';
      actionDescription = `Uma nova ameaça foi identificada no sistema.`;
    } else if (action === 'status_changed' && details) {
      actionTitle = '🔄 Status de Ameaça Alterado';
      actionDescription = `O status da ameaça foi alterado de <strong>${details.oldStatus}</strong> para <strong>${details.newStatus}</strong>.`;
      
      if (details.user) {
        actionDescription += `<br><strong>Alterado por:</strong> ${details.user.firstName} ${details.user.lastName}`;
      }
      
      if (details.justification) {
        actionDescription += `<br><strong>Justificativa:</strong> ${details.justification}`;
      }
    }

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Notificação SamurEye</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f3f4f6;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f3f4f6; padding: 20px;">
          <tr>
            <td align="center">
              <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px;">SamurEye</h1>
                    <p style="margin: 10px 0 0 0; color: #e0e7ff; font-size: 14px;">Plataforma de Validação de Exposição Adversarial</p>
                  </td>
                </tr>
                
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px 0; color: #111827; font-size: 20px;">${actionTitle}</h2>
                    
                    <p style="margin: 0 0 20px 0; color: #4b5563; line-height: 1.6;">
                      ${actionDescription}
                    </p>
                    
                    <!-- Threat Card -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="border: 2px solid ${severityColor}; border-radius: 6px; margin-bottom: 20px;">
                      <tr>
                        <td style="padding: 20px;">
                          <table width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                              <td>
                                <div style="display: inline-block; background-color: ${severityColor}; color: #ffffff; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 12px;">
                                  ${threat.severity}
                                </div>
                              </td>
                            </tr>
                          </table>
                          
                          <h3 style="margin: 0 0 10px 0; color: #111827; font-size: 18px;">${threat.title}</h3>
                          
                          ${threat.description ? `
                            <p style="margin: 0 0 15px 0; color: #6b7280; line-height: 1.5;">
                              ${threat.description}
                            </p>
                          ` : ''}
                          
                          <table width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                              <td style="padding: 8px 0; border-top: 1px solid #e5e7eb;">
                                <strong style="color: #374151;">Status:</strong> 
                                <span style="color: #6b7280;">${threat.status}</span>
                              </td>
                            </tr>
                            <tr>
                              <td style="padding: 8px 0; border-top: 1px solid #e5e7eb;">
                                <strong style="color: #374151;">ID:</strong> 
                                <span style="color: #6b7280; font-family: monospace; font-size: 12px;">${threat.id}</span>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- Action Button -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-top: 30px;">
                      <tr>
                        <td align="center">
                          <a href="${threatUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-weight: 600;">
                            Ver Detalhes da Ameaça
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                
                <!-- Footer -->
                <tr>
                  <td style="background-color: #f9fafb; padding: 20px; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; color: #6b7280; font-size: 12px;">
                      Esta é uma notificação automática do SamurEye.<br>
                      Para alterar suas preferências de notificação, acesse as configurações do sistema.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `;
  }
}

export const emailService = new EmailService();
