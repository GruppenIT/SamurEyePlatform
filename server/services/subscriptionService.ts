import { storage } from '../storage';
import { encryptionService } from './encryption';
import { telemetryService } from './telemetryService';
import type { ApplianceSubscription } from '@shared/schema';

const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const GRACE_PERIOD_HOURS = 72;

/**
 * SubscriptionService
 *
 * Manages the appliance's connection to the SamurEye central console:
 * - API key activation/deactivation
 * - Periodic heartbeat (telemetry + subscription check)
 * - Grace period when console is unreachable
 * - Read-only mode enforcement when subscription expires
 */
class SubscriptionService {
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private cachedStatus: ApplianceSubscription | null = null;

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
  }

  private startHeartbeat() {
    this.stop(); // Clear any existing interval

    // Run first heartbeat after 30s (let server fully start)
    setTimeout(() => {
      this.sendHeartbeat();
    }, 30_000);

    // Then every 5 minutes
    this.intervalId = setInterval(() => {
      this.sendHeartbeat();
    }, HEARTBEAT_INTERVAL_MS);

    console.log(`🔄 Heartbeat configurado: a cada ${HEARTBEAT_INTERVAL_MS / 1000 / 60} minutos`);
  }

  /**
   * Activate this appliance with an API key from the central console
   */
  async activate(apiKeyPlain: string, userId: string): Promise<{ success: boolean; error?: string; subscription?: ApplianceSubscription }> {
    try {
      // Get or create subscription record
      let sub = await storage.getSubscription();
      const applianceId = sub?.applianceId || crypto.randomUUID();

      // Encrypt the API key
      const encrypted = encryptionService.encryptCredential(apiKeyPlain);

      // Try to activate with the console
      const consoleUrl = sub?.consoleBaseUrl || 'https://api.samureye.com.br';
      const response = await fetch(`${consoleUrl}/v1/appliance/activate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyPlain}`,
        },
        body: JSON.stringify({
          applianceId,
          version: process.env.APP_VERSION || '1.0.0',
          hostname: (await import('os')).hostname(),
        }),
        signal: AbortSignal.timeout(15_000),
      });

      if (!response.ok) {
        const body = await response.text();
        return { success: false, error: `Console respondeu com status ${response.status}: ${body}` };
      }

      const data = await response.json();

      // Save to DB
      const updated = await storage.upsertSubscription({
        applianceId,
        apiKey: encrypted.secretEncrypted,
        apiKeyDek: encrypted.dekEncrypted,
        status: 'active',
        tenantId: data.tenantId,
        tenantName: data.tenantName,
        plan: data.plan,
        expiresAt: new Date(data.expiresAt),
        features: data.features || [],
        lastHeartbeatAt: new Date(),
        lastHeartbeatError: null,
        consecutiveFailures: 0,
        graceDeadline: null,
        consoleBaseUrl: consoleUrl,
        activatedAt: new Date(),
      }, userId);

      this.cachedStatus = updated;
      this.startHeartbeat();

      return { success: true, subscription: updated };
    } catch (error: any) {
      const message = error.name === 'TimeoutError'
        ? 'Timeout ao conectar com a console central (15s)'
        : `Erro ao ativar: ${error.message}`;
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
   */
  async sendHeartbeat(): Promise<void> {
    const sub = await storage.getSubscription();
    if (!sub || !sub.apiKey) return;

    try {
      const apiKeyPlain = this.decryptApiKey(sub);
      if (!apiKeyPlain) {
        console.error('❌ Não foi possível descriptografar a chave de API');
        return;
      }

      // Collect telemetry
      const telemetry = await telemetryService.collect(sub.applianceId);

      const response = await fetch(`${sub.consoleBaseUrl}/v1/appliance/heartbeat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKeyPlain}`,
        },
        body: JSON.stringify(telemetry),
        signal: AbortSignal.timeout(15_000),
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`Console respondeu com status ${response.status}: ${body}`);
      }

      const data = await response.json();

      // Update local subscription cache with console response
      this.cachedStatus = await storage.updateHeartbeatSuccess({
        active: data.subscription.active,
        plan: data.subscription.plan,
        expiresAt: data.subscription.expiresAt,
        features: data.subscription.features || [],
        tenantId: data.subscription?.tenantId,
        tenantName: data.subscription?.tenantName,
      });

      console.log(`💚 Heartbeat OK | plan=${data.subscription.plan} | expires=${data.subscription.expiresAt}`);
    } catch (error: any) {
      const message = error.name === 'TimeoutError'
        ? 'Timeout ao conectar com a console central'
        : error.message;

      this.cachedStatus = await storage.updateHeartbeatFailure(message);
      console.warn(`💛 Heartbeat falhou (${this.cachedStatus.consecutiveFailures}x): ${message}`);
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
