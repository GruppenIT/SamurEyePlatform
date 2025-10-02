import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { EmailSettings } from '@shared/schema';
import { EncryptionService } from './encryption';
import { ConfidentialClientApplication } from '@azure/msal-node';
import { google } from 'googleapis';

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

  private translateStatus(status: string): string {
    const statusMap: Record<string, string> = {
      'open': 'Aberta',
      'investigating': 'Investigando',
      'mitigated': 'Mitigada',
      'closed': 'Fechada',
      'hibernated': 'Hibernada',
      'accepted_risk': 'Risco Aceito',
    };
    return statusMap[status] || status;
  }

  private translateSeverity(severity: string): string {
    const severityMap: Record<string, string> = {
      'critical': 'Crítica',
      'high': 'Alta',
      'medium': 'Média',
      'low': 'Baixa',
    };
    return severityMap[severity] || severity;
  }

  private async getGmailAccessToken(settings: EmailSettings): Promise<string> {
    if (!settings.oauth2ClientId || !settings.oauth2ClientSecret || !settings.oauth2ClientSecretDek) {
      throw new Error('OAuth2 Gmail não configurado corretamente');
    }

    if (!settings.oauth2RefreshToken || !settings.oauth2RefreshTokenDek) {
      throw new Error('Refresh token do Gmail não configurado');
    }

    // Decrypt credentials
    const clientSecret = this.encryptionService.decryptCredential(
      settings.oauth2ClientSecret,
      settings.oauth2ClientSecretDek
    );

    const refreshToken = this.encryptionService.decryptCredential(
      settings.oauth2RefreshToken,
      settings.oauth2RefreshTokenDek
    );

    // Create OAuth2 client
    const oauth2Client = new google.auth.OAuth2(
      settings.oauth2ClientId,
      clientSecret,
      'https://developers.google.com/oauthplayground'
    );

    oauth2Client.setCredentials({
      refresh_token: refreshToken,
    });

    // Get access token
    const { token } = await oauth2Client.getAccessToken();
    if (!token) {
      throw new Error('Falha ao obter access token do Gmail');
    }

    return token;
  }

  private async getMicrosoftAccessToken(settings: EmailSettings): Promise<string> {
    if (!settings.oauth2ClientId || !settings.oauth2ClientSecret || !settings.oauth2ClientSecretDek) {
      throw new Error('OAuth2 Microsoft não configurado corretamente');
    }

    if (!settings.oauth2TenantId) {
      throw new Error('Tenant ID do Microsoft não configurado');
    }

    if (!settings.oauth2RefreshToken || !settings.oauth2RefreshTokenDek) {
      throw new Error('Refresh token do Microsoft não configurado');
    }

    // Decrypt credentials
    const clientSecret = this.encryptionService.decryptCredential(
      settings.oauth2ClientSecret,
      settings.oauth2ClientSecretDek
    );

    const refreshToken = this.encryptionService.decryptCredential(
      settings.oauth2RefreshToken,
      settings.oauth2RefreshTokenDek
    );

    // Create MSAL app
    const msalConfig = {
      auth: {
        clientId: settings.oauth2ClientId,
        clientSecret: clientSecret,
        authority: `https://login.microsoftonline.com/${settings.oauth2TenantId}`,
      },
    };

    const cca = new ConfidentialClientApplication(msalConfig);

    try {
      // Try to get token using refresh token
      const tokenRequest = {
        refreshToken: refreshToken,
        scopes: ['https://outlook.office365.com/.default'],
      };

      const response = await cca.acquireTokenByRefreshToken(tokenRequest);
      if (!response || !response.accessToken) {
        throw new Error('Falha ao obter access token do Microsoft');
      }

      return response.accessToken;
    } catch (error) {
      console.error('Erro ao obter access token Microsoft:', error);
      throw new Error(`Falha ao obter access token do Microsoft: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  async createTransporter(settings: EmailSettings): Promise<Transporter> {
    const config: any = {
      host: settings.smtpHost,
      port: settings.smtpPort,
      secure: settings.smtpSecure,
    };

    // Configure authentication based on authType
    if (settings.authType === 'password') {
      // Basic password authentication
      if (!settings.authPassword || !settings.dekEncrypted || !settings.authUser) {
        throw new Error('Credenciais de senha não configuradas corretamente');
      }

      const password = this.encryptionService.decryptCredential(
        settings.authPassword,
        settings.dekEncrypted
      );

      config.auth = {
        user: settings.authUser,
        pass: password,
      };

    } else if (settings.authType === 'oauth2_gmail') {
      // Gmail OAuth2
      const accessToken = await this.getGmailAccessToken(settings);

      config.auth = {
        type: 'OAuth2',
        user: settings.fromEmail,
        clientId: settings.oauth2ClientId,
        clientSecret: await (async () => {
          if (!settings.oauth2ClientSecret || !settings.oauth2ClientSecretDek) return '';
          return this.encryptionService.decryptCredential(
            settings.oauth2ClientSecret,
            settings.oauth2ClientSecretDek
          );
        })(),
        refreshToken: await (async () => {
          if (!settings.oauth2RefreshToken || !settings.oauth2RefreshTokenDek) return '';
          return this.encryptionService.decryptCredential(
            settings.oauth2RefreshToken,
            settings.oauth2RefreshTokenDek
          );
        })(),
        accessToken: accessToken,
      };

    } else if (settings.authType === 'oauth2_microsoft') {
      // Microsoft OAuth2
      const accessToken = await this.getMicrosoftAccessToken(settings);

      config.auth = {
        type: 'OAuth2',
        user: settings.fromEmail,
        accessToken: accessToken,
      };

      config.tls = {
        ciphers: 'SSLv3',
      };
    }

    // Configure TLS for port 587
    if (!settings.smtpSecure && settings.smtpPort === 587) {
      config.requireTLS = true;
      if (!config.tls) {
        config.tls = {};
      }
      config.tls.servername = settings.smtpHost;
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
    const currentDate = new Date().toLocaleString('pt-BR', { 
      dateStyle: 'long', 
      timeStyle: 'short',
      timeZone: 'America/Sao_Paulo'
    });

    if (action === 'created') {
      actionTitle = 'RELATÓRIO DE THREAT INTELLIGENCE';
      actionDescription = `
        <div style="background-color: #fef2f2; border-left: 4px solid ${severityColor}; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
          <strong style="color: #991b1b; font-size: 14px;">⚠️ NOVA AMEAÇA IDENTIFICADA</strong>
          <p style="margin: 8px 0 0 0; color: #7f1d1d; font-size: 13px; line-height: 1.5;">
            Nossa plataforma de validação contínua de exposição adversarial identificou uma nova ameaça em seu ambiente. 
            Esta notificação foi gerada automaticamente pelo sistema de detecção e requer atenção imediata de sua equipe de segurança.
          </p>
        </div>
        <p style="margin: 0; color: #374151; font-size: 13px;">
          <strong>Data/Hora da Detecção:</strong> ${currentDate}
        </p>
      `;
    } else if (action === 'status_changed' && details) {
      actionTitle = 'ATUALIZAÇÃO DE STATUS - THREAT INTELLIGENCE';
      actionDescription = `
        <div style="background-color: #eff6ff; border-left: 4px solid #2563eb; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
          <strong style="color: #1e40af; font-size: 14px;">🔄 MUDANÇA DE STATUS REGISTRADA</strong>
          <p style="margin: 8px 0 0 0; color: #1e3a8a; font-size: 13px; line-height: 1.5;">
            O status desta ameaça foi atualizado no sistema de gerenciamento de incidentes. 
            As informações detalhadas sobre a alteração estão documentadas abaixo.
          </p>
        </div>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom: 20px;">
          <tr>
            <td style="padding: 8px 12px; background-color: #f9fafb; border-radius: 4px;">
              <p style="margin: 0; color: #374151; font-size: 13px; line-height: 1.8;">
                <strong>Status Anterior:</strong> <span style="color: #6b7280;">${this.translateStatus(details.oldStatus || '')}</span><br>
                <strong>Status Atual:</strong> <span style="color: #6b7280;">${this.translateStatus(details.newStatus || '')}</span><br>
                <strong>Data/Hora da Alteração:</strong> <span style="color: #6b7280;">${currentDate}</span>
                ${details.user ? `<br><strong>Analista Responsável:</strong> <span style="color: #6b7280;">${details.user.firstName} ${details.user.lastName}</span>` : ''}
                ${details.justification ? `<br><strong>Justificativa Técnica:</strong> <span style="color: #6b7280;">${details.justification}</span>` : ''}
              </p>
            </td>
          </tr>
        </table>
      `;
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
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: 1px;">SamurEye</h1>
                    <p style="margin: 8px 0 0 0; color: #e0e7ff; font-size: 13px; font-weight: 500;">Plataforma de Validação de Exposição Adversarial</p>
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
                                  ${this.translateSeverity(threat.severity)}
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
                                <span style="color: #6b7280;">${this.translateStatus(threat.status)}</span>
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
                  <td style="background-color: #f9fafb; padding: 25px 20px; text-align: center; border-top: 2px solid #e5e7eb;">
                    <p style="margin: 0 0 12px 0; color: #4b5563; font-size: 11px; line-height: 1.6; font-weight: 500;">
                      Esta é uma notificação automática do sistema de monitoramento contínuo.<br>
                      Para alterar suas preferências de notificação, acesse as Configurações do Sistema.
                    </p>
                    
                    <div style="margin: 15px 0; padding: 15px 0; border-top: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb;">
                      <p style="margin: 0 0 6px 0; color: #374151; font-size: 12px; font-weight: 600;">
                        SamurEye™
                      </p>
                      <p style="margin: 0; color: #6b7280; font-size: 11px; line-height: 1.5;">
                        Solução de segurança desenvolvida e suportada por<br>
                        <strong style="color: #4b5563;">Gruppen IT Security</strong>
                      </p>
                    </div>
                    
                    <p style="margin: 12px 0 0 0;">
                      <a href="https://www.samureye.com.br" style="color: #667eea; text-decoration: none; font-size: 11px; font-weight: 600;">
                        www.samureye.com.br
                      </a>
                    </p>
                    
                    <p style="margin: 10px 0 0 0; color: #9ca3af; font-size: 10px;">
                      © ${new Date().getFullYear()} Gruppen IT Security. Todos os direitos reservados.
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
