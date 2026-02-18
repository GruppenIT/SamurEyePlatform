import { storage } from '../storage';
import { encryptionService } from './encryption';
import { telemetryService } from './telemetryService';
import { systemUpdateService } from './systemUpdateService';
import type { ApplianceSubscription, ConsoleCommand, CommandResult } from '@shared/schema';
import { APP_VERSION } from '../version';

const HEARTBEAT_ACTIVE_INTERVAL_MS = 5 * 60 * 1000;  // 5 minutes (active)
const HEARTBEAT_STANDBY_INTERVAL_MS = 30 * 60 * 1000; // 30 minutes (standby)
const HEARTBEAT_RETRY_DELAYS = [10_000, 20_000, 40_000, 80_000]; // backoff: 10s, 20s, 40s, 80s
const GRACE_PERIOD_HOURS = 72;

/**
 * SubscriptionService
 *
 * Manages the appliance's connection to the SamurEye central console:
 * - API key activation/deactivation
 * - Periodic heartbeat (telemetry + subscription check)
 * - Standby mode with reduced heartbeat when subscription inactive
 * - Retry with exponential backoff on heartbeat failure
 * - Grace period when console is unreachable
 * - Read-only mode enforcement when subscription expires
 */
class SubscriptionService {
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private startupTimeoutId: ReturnType<typeof setTimeout> | null = null;
  private cachedStatus: ApplianceSubscription | null = null;
  private inStandby = false;

  /**
   * Start the heartbeat loop (called on server boot)
   */
  start() {
    console.log('🔑 Iniciando serviço de subscrição...');

    // Load cached status from DB
    this.refreshCache().then(() => {
      // Only start heartbeat if subscription is configured
      if (this.cachedStatus && this.cachedStatus.apiKey) {
        this.startHeartbeat();
      }
    });

    console.log('✅ Serviço de subscrição iniciado');
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (this.startupTimeoutId) {
      clearTimeout(this.startupTimeoutId);
      this.startupTimeoutId = null;
    }
  }

  private startHeartbeat() {
    this.stop(); // Clear any existing interval

    const interval = this.inStandby ? HEARTBEAT_STANDBY_INTERVAL_MS : HEARTBEAT_ACTIVE_INTERVAL_MS;

    // Run first heartbeat after 30s (let server fully start)
    this.startupTimeoutId = setTimeout(() => {
      this.sendHeartbeat();
    }, 30_000);

    // Then at the configured interval
    this.intervalId = setInterval(() => {
      this.sendHeartbeat();
    }, interval);

    console.log(`🔄 Heartbeat configurado: a cada ${interval / 1000 / 60} minutos${this.inStandby ? ' (standby)' : ''}`);
  }

  /**
   * Switch heartbeat interval based on subscription state
   */
  private adjustHeartbeatInterval(active: boolean) {
    const shouldBeStandby = !active;
    if (shouldBeStandby !== this.inStandby) {
      this.inStandby = shouldBeStandby;
      console.log(`🔄 Modo ${this.inStandby ? 'standby (30min)' : 'ativo (5min)'} — reajustando heartbeat`);
      // Restart the interval with the new timing
      if (this.intervalId) {
        this.stop();
        this.intervalId = setInterval(() => {
          this.sendHeartbeat();
        }, this.inStandby ? HEARTBEAT_STANDBY_INTERVAL_MS : HEARTBEAT_ACTIVE_INTERVAL_MS);
      }
    }
  }

  /**
   * Activate this appliance with an API key from the central console
   */
  async activate(apiKeyPlain: string, consoleUrl: string, userId: string): Promise<{ success: boolean; error?: string; subscription?: ApplianceSubscription }> {
    // Normalize console URL (remove trailing slash)
    consoleUrl = consoleUrl.replace(/\/+$/, '');
    const activateUrl = `${consoleUrl}/v1/appliance/activate`;

    try {
      // Get or create subscription record
      let sub = await storage.getSubscription();
      const applianceId = sub?.applianceId || crypto.randomUUID();

      // Encrypt the API key
      const encrypted = encryptionService.encryptCredential(apiKeyPlain);

      console.log(`🔑 Tentando ativar appliance ${applianceId} em ${activateUrl}...`);

      // Try to activate with the console
      const response = await fetch(activateUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyPlain}`,
        },
        body: JSON.stringify({
          applianceId,
          version: APP_VERSION,
          hostname: (await import('os')).hostname(),
        }),
        signal: AbortSignal.timeout(15_000),
      });

      if (response.status === 401) {
        return { success: false, error: 'Chave de API inválida ou revogada. Verifique a chave fornecida pela console central.' };
      }

      if (response.status === 403) {
        // Tenant inactive/expired — save in standby mode
        const updated = await storage.upsertSubscription({
          applianceId,
          apiKey: encrypted.secretEncrypted,
          apiKeyDek: encrypted.dekEncrypted,
          status: 'expired',
          features: [],
          lastHeartbeatAt: new Date(),
          lastHeartbeatError: 'Tenant inativo ou expirado (403)',
          consecutiveFailures: 0,
          graceDeadline: null,
          consoleBaseUrl: consoleUrl,
          activatedAt: new Date(),
        }, userId);
        this.cachedStatus = updated;
        this.inStandby = true;
        this.startHeartbeat();
        return { success: false, error: 'Tenant inativo ou expirado. O appliance entrará em modo standby e verificará periodicamente se foi reativado.' };
      }

      if (!response.ok) {
        const body = await response.text();
        return { success: false, error: `Console respondeu com status ${response.status}: ${body}` };
      }

      const data = await response.json();

      // Save to DB (including subscription details from activation response)
      const subData = data.subscription || data;
      const updated = await storage.upsertSubscription({
        applianceId,
        apiKey: encrypted.secretEncrypted,
        apiKeyDek: encrypted.dekEncrypted,
        status: 'active',
        tenantId: data.tenantId || subData.tenantId,
        tenantName: data.tenantName || subData.tenantName,
        plan: subData.plan || data.plan,
        planSlug: subData.planSlug || null,
        maxAppliances: subData.maxAppliances ?? null,
        isTrial: subData.isTrial ?? false,
        durationDays: subData.durationDays ?? null,
        consoleMessage: subData.message ?? null,
        expiresAt: (subData.expiresAt || data.expiresAt) ? new Date(subData.expiresAt || data.expiresAt) : null,
        features: subData.features || data.features || [],
        lastHeartbeatAt: new Date(),
        lastHeartbeatError: null,
        consecutiveFailures: 0,
        graceDeadline: null,
        consoleBaseUrl: consoleUrl,
        activatedAt: new Date(),
      }, userId);

      this.cachedStatus = updated;
      this.inStandby = false;
      this.startHeartbeat();

      return { success: true, subscription: updated };
    } catch (error: any) {
      // Provide detailed, actionable error messages
      let message: string;
      const cause = error.cause;

      if (error.name === 'TimeoutError') {
        message = `Timeout ao conectar com ${activateUrl} (15s). Verifique se a URL está correta e acessível a partir deste appliance.`;
      } else if (cause?.code === 'ENOTFOUND') {
        message = `DNS não resolvido: o host "${new URL(consoleUrl).hostname}" não foi encontrado. Verifique o DNS do appliance ou a URL da console.`;
      } else if (cause?.code === 'ECONNREFUSED') {
        message = `Conexão recusada por ${consoleUrl}. Verifique se a console central está rodando e a porta está correta.`;
      } else if (cause?.code === 'ECONNRESET' || cause?.code === 'EPIPE') {
        message = `Conexão interrompida com ${consoleUrl}. Pode ser um firewall bloqueando ou problema de TLS/certificado.`;
      } else if (cause?.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || cause?.code === 'CERT_HAS_EXPIRED' || cause?.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || cause?.code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
        message = `Erro de certificado TLS ao conectar em ${consoleUrl}: ${cause.code}. Se estiver usando certificado auto-assinado, configure NODE_EXTRA_CA_CERTS no appliance.`;
      } else if (error.message?.includes('fetch failed')) {
        message = `Não foi possível conectar em ${activateUrl}. Verifique: (1) se a URL está correta, (2) se o DNS resolve, (3) se não há firewall bloqueando. Erro: ${cause?.message || cause?.code || error.message}`;
      } else {
        message = `Erro ao conectar em ${activateUrl}: ${error.message}`;
      }

      console.error(`❌ Ativação falhou: ${message}`);
      return { success: false, error: message };
    }
  }

  /**
   * Deactivate the appliance (remove API key)
   */
  async deactivate(userId: string): Promise<void> {
    const sub = await storage.getSubscription();
    if (!sub) return;

    // Notify console if possible
    try {
      const apiKeyPlain = this.decryptApiKey(sub);
      if (apiKeyPlain) {
        await fetch(`${sub.consoleBaseUrl}/v1/appliance/deactivate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKeyPlain}`,
          },
          body: JSON.stringify({ applianceId: sub.applianceId }),
          signal: AbortSignal.timeout(10_000),
        });
      }
    } catch {
      // Best-effort, don't block deactivation
    }

    await storage.upsertSubscription({
      apiKey: null,
      apiKeyDek: null,
      status: 'not_configured',
      tenantId: null,
      tenantName: null,
      plan: null,
      expiresAt: null,
      features: [],
      lastHeartbeatAt: null,
      lastHeartbeatError: null,
      consecutiveFailures: 0,
      graceDeadline: null,
      activatedAt: null,
    }, userId);

    this.cachedStatus = null;
    this.stop();
  }

  /**
   * Send heartbeat to central console (telemetry + subscription check)
   * Retries with exponential backoff (10s, 20s, 40s, 80s) on transient failures.
   */
  async sendHeartbeat(): Promise<void> {
    const sub = await storage.getSubscription();
    if (!sub || !sub.apiKey) return;

    const apiKeyPlain = this.decryptApiKey(sub);
    if (!apiKeyPlain) {
      console.error('❌ Não foi possível descriptografar a chave de API');
      return;
    }

    // Collect telemetry once (reuse across retries)
    const telemetry = await telemetryService.collect(sub.applianceId);
    const heartbeatUrl = `${sub.consoleBaseUrl}/v1/appliance/heartbeat`;

    // Attach unreported command results to the heartbeat payload
    const unreported = await storage.getUnreportedCommandResults();
    if (unreported.length > 0) {
      telemetry.commandResults = unreported.map(cmd => ({
        id: cmd.id,
        // Console expects 'acknowledged' for in-progress commands (not 'running')
        status: (cmd.status === 'running' ? 'acknowledged' : cmd.status) as 'acknowledged' | 'completed' | 'failed',
        result: cmd.result || undefined,
        error: cmd.error || undefined,
        startedAt: cmd.startedAt?.toISOString(),
        finishedAt: cmd.finishedAt?.toISOString(),
      }));
    }

    for (let attempt = 0; attempt <= HEARTBEAT_RETRY_DELAYS.length; attempt++) {
      try {
        const response = await fetch(heartbeatUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKeyPlain}`,
          },
          body: JSON.stringify(telemetry),
          signal: AbortSignal.timeout(15_000),
        });

        // HTTP 401: API key invalid/revoked — stop heartbeat, require manual intervention
        if (response.status === 401) {
          console.error('🔴 HTTP 401 — Chave de API inválida ou revogada. Heartbeat interrompido. Intervenção manual necessária.');
          this.cachedStatus = await storage.updateHeartbeatFailure(
            'Chave de API inválida ou revogada (401). Heartbeat interrompido.',
          );
          this.stop();
          return;
        }

        // HTTP 403: Tenant inactive/suspended — enter standby mode
        if (response.status === 403) {
          console.warn('🟠 HTTP 403 — Tenant inativo ou suspenso. Entrando em modo standby.');
          this.cachedStatus = await storage.updateHeartbeatFailure(
            'Tenant inativo ou suspenso (403). Modo standby ativado.',
          );
          this.adjustHeartbeatInterval(false);
          return;
        }

        // HTTP 4xx (other than 401/403 handled above): client error — do not retry
        if (response.status >= 400 && response.status < 500) {
          const body = await response.text();
          this.cachedStatus = await storage.updateHeartbeatFailure(
            `Console rejeitou os dados (${response.status})`,
          );
          throw Object.assign(
            new Error(`Console respondeu com status ${response.status}: ${body}`),
            { nonRetryable: true },
          );
        }

        if (!response.ok) {
          throw new Error(`Console respondeu com status ${response.status}: ${await response.text()}`);
        }

        const data = await response.json();

        // Mark command results as reported (console received them)
        if (unreported.length > 0) {
          await storage.markCommandsReported(unreported.map(c => c.id));
        }

        // Update local subscription cache with console response
        this.cachedStatus = await storage.updateHeartbeatSuccess({
          active: data.subscription.active,
          plan: data.subscription.plan,
          expiresAt: data.subscription.expiresAt,
          features: data.subscription.features || [],
          tenantId: data.subscription?.tenantId,
          tenantName: data.subscription?.tenantName,
          planSlug: data.subscription?.planSlug,
          maxAppliances: data.subscription?.maxAppliances,
          isTrial: data.subscription?.isTrial,
          durationDays: data.subscription?.durationDays,
          message: data.subscription?.message,
        });

        // Adjust interval based on subscription status
        this.adjustHeartbeatInterval(data.subscription.active);

        console.log(`💚 Heartbeat OK | plan=${data.subscription.plan} | active=${data.subscription.active} | expires=${data.subscription.expiresAt || 'never'}`);

        // Process commands from console (fire-and-forget, don't block heartbeat)
        if (data.commands && Array.isArray(data.commands) && data.commands.length > 0) {
          this.processCommands(data.commands).catch(err => {
            console.error('❌ Erro ao processar comandos da console:', err.message);
          });
        }

        return; // Success — exit retry loop

      } catch (error: any) {
        const message = error.name === 'TimeoutError'
          ? 'Timeout ao conectar com a console central'
          : error.message;

        // Client errors (4xx) won't fix themselves — fail immediately
        if (error.nonRetryable) {
          console.error(`🔴 Heartbeat falhou (não retentável): ${message}`);
          throw error;
        }

        // If we still have retries left, wait and try again
        if (attempt < HEARTBEAT_RETRY_DELAYS.length) {
          const delay = HEARTBEAT_RETRY_DELAYS[attempt];
          console.warn(`💛 Heartbeat falhou (tentativa ${attempt + 1}/${HEARTBEAT_RETRY_DELAYS.length + 1}): ${message}. Retry em ${delay / 1000}s...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        // All retries exhausted — record failure
        this.cachedStatus = await storage.updateHeartbeatFailure(message);
        console.warn(`💛 Heartbeat falhou após ${HEARTBEAT_RETRY_DELAYS.length + 1} tentativas (${this.cachedStatus.consecutiveFailures}x consecutivas): ${message}`);
      }
    }
  }

  /**
   * Process commands received from the central console via heartbeat response.
   * Each command is saved to DB and dispatched by type.
   */
  private async processCommands(commands: ConsoleCommand[]): Promise<void> {
    // Save all to DB first (dedup built into storage)
    await storage.saveReceivedCommands(commands);

    for (const cmd of commands) {
      console.log(`📥 Comando recebido: type=${cmd.type} id=${cmd.id}`);

      switch (cmd.type) {
        case 'system_update':
          // Run update asynchronously — don't block command processing
          systemUpdateService.execute(cmd.id, cmd.params || {}).then(result => {
            if (result.success) {
              console.log(`✅ Update concluído: ${result.previousVersion} → ${result.newVersion}`);
            } else {
              console.error(`❌ Update falhou na fase "${result.phase}": ${result.error}`);
            }
          });
          break;

        case 'restart_service':
          this.handleRestartService(cmd.id).catch(err => {
            console.error(`❌ Restart falhou: ${err.message}`);
          });
          break;

        default:
          console.warn(`⚠️  Comando desconhecido: type=${cmd.type} — ignorando`);
          await storage.updateCommandStatus(cmd.id, 'failed', {
            error: `Tipo de comando não suportado: ${cmd.type}`,
          });
      }
    }
  }

  private async handleRestartService(commandId: string): Promise<void> {
    await storage.updateCommandStatus(commandId, 'running');
    try {
      const { execSync } = await import('child_process');
      const serviceName = process.env.SERVICE_NAME || 'samureye-api';
      execSync(`systemctl restart ${serviceName}`, { timeout: 30_000 });
      await storage.updateCommandStatus(commandId, 'completed', {
        result: { service: serviceName },
      });
    } catch (err: any) {
      await storage.updateCommandStatus(commandId, 'failed', {
        error: err.message,
      });
    }
  }

  /**
   * Check if the appliance should be in read-only mode
   */
  isReadOnly(): boolean {
    if (!this.cachedStatus) return false; // Not configured = full access
    if (this.cachedStatus.status === 'not_configured') return false;
    if (this.cachedStatus.status === 'active') return false;
    if (this.cachedStatus.status === 'grace_period') return false;

    // expired or unreachable = read-only
    return true;
  }

  /**
   * Get subscription status for the frontend
   */
  async getStatus(): Promise<{
    configured: boolean;
    applianceId: string | null;
    status: string;
    tenantName: string | null;
    plan: string | null;
    planSlug: string | null;
    maxAppliances: number | null;
    isTrial: boolean;
    durationDays: number | null;
    consoleMessage: string | null;
    expiresAt: string | null;
    features: string[];
    lastHeartbeatAt: string | null;
    lastHeartbeatError: string | null;
    consecutiveFailures: number;
    graceDeadline: string | null;
    consoleBaseUrl: string;
    activatedAt: string | null;
    readOnly: boolean;
  }> {
    await this.refreshCache();
    const sub = this.cachedStatus;

    if (!sub || sub.status === 'not_configured') {
      return {
        configured: false,
        applianceId: sub?.applianceId || null,
        status: 'not_configured',
        tenantName: null,
        plan: null,
        planSlug: null,
        maxAppliances: null,
        isTrial: false,
        durationDays: null,
        consoleMessage: null,
        expiresAt: null,
        features: [],
        lastHeartbeatAt: null,
        lastHeartbeatError: null,
        consecutiveFailures: 0,
        graceDeadline: null,
        consoleBaseUrl: sub?.consoleBaseUrl || 'https://api.samureye.com.br',
        activatedAt: null,
        readOnly: false,
      };
    }

    return {
      configured: true,
      applianceId: sub.applianceId,
      status: sub.status,
      tenantName: sub.tenantName,
      plan: sub.plan,
      planSlug: sub.planSlug || null,
      maxAppliances: sub.maxAppliances ?? null,
      isTrial: sub.isTrial ?? false,
      durationDays: sub.durationDays ?? null,
      consoleMessage: sub.consoleMessage || null,
      expiresAt: sub.expiresAt?.toISOString() || null,
      features: sub.features as string[] || [],
      lastHeartbeatAt: sub.lastHeartbeatAt?.toISOString() || null,
      lastHeartbeatError: sub.lastHeartbeatError,
      consecutiveFailures: sub.consecutiveFailures,
      graceDeadline: sub.graceDeadline?.toISOString() || null,
      consoleBaseUrl: sub.consoleBaseUrl || 'https://api.samureye.com.br',
      activatedAt: sub.activatedAt?.toISOString() || null,
      readOnly: this.isReadOnly(),
    };
  }

  private async refreshCache(): Promise<void> {
    this.cachedStatus = (await storage.getSubscription()) || null;
  }

  private decryptApiKey(sub: ApplianceSubscription): string | null {
    if (!sub.apiKey || !sub.apiKeyDek) return null;
    try {
      return encryptionService.decryptCredential(sub.apiKey, sub.apiKeyDek);
    } catch {
      return null;
    }
  }
}

export const subscriptionService = new SubscriptionService();
