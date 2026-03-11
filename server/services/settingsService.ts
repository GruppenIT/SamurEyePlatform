import { storage } from '../storage';
import { createLogger } from '../lib/logger';

const log = createLogger('settings');

export interface SystemSettings {
  adPasswordAgeLimitDays: number;
  adInactiveUserLimitDays: number;
  adMaxPrivilegedGroupMembers: number;
  adComputerInactiveDays: number;
}

export class SettingsService {
  private static readonly DEFAULT_SETTINGS: Record<string, any> = {
    'ad.passwordAgeLimitDays': 90,
    'ad.inactiveUserLimitDays': 180,
    'ad.maxPrivilegedGroupMembers': 5,
    'ad.computerInactiveDays': 90,
    'systemName': 'SamurEye',
    'sessionTimeout': 3600,
    'enableNotifications': true,
  };

  /**
   * Inicializa configurações padrão do sistema
   */
  static async initializeDefaultSettings(): Promise<void> {
    log.info('inicializando configurações padrão do sistema');
    
    try {
      // Verificar se há usuários no sistema
      const users = await storage.getAllUsers();
      
      if (users.length === 0) {
        log.warn('nenhum usuário encontrado - configurações serão criadas após primeiro usuário');
        return;
      }
      
      // Usar o primeiro usuário admin encontrado, ou o primeiro usuário se não houver admin
      const adminUser = users.find(u => u.role === 'global_administrator') || users[0];
      
      for (const [key, value] of Object.entries(this.DEFAULT_SETTINGS)) {
        const existingSetting = await storage.getSetting(key);
        
        if (!existingSetting) {
          await storage.setSetting(key, value, adminUser.id);
          log.info({ key, value }, 'configuração criada');
        }
      }
      
      log.info('configurações padrão inicializadas com sucesso');
    } catch (error) {
      log.error({ err: error }, 'erro ao inicializar configurações padrão');
    }
  }

  /**
   * Obtém configurações específicas para higiene AD
   */
  static async getADHygieneSettings(): Promise<SystemSettings> {
    try {
      const [
        passwordAgeLimit,
        inactiveUserLimit,
        maxPrivilegedMembers,
        computerInactiveDays
      ] = await Promise.all([
        storage.getSetting('ad.passwordAgeLimitDays'),
        storage.getSetting('ad.inactiveUserLimitDays'),
        storage.getSetting('ad.maxPrivilegedGroupMembers'),
        storage.getSetting('ad.computerInactiveDays')
      ]);

      return {
        adPasswordAgeLimitDays: passwordAgeLimit?.value || 90,
        adInactiveUserLimitDays: inactiveUserLimit?.value || 180,
        adMaxPrivilegedGroupMembers: maxPrivilegedMembers?.value || 5,
        adComputerInactiveDays: computerInactiveDays?.value || 90,
      };
    } catch (error) {
      log.error({ err: error }, 'erro ao obter configurações AD');
      // Retornar valores padrão em caso de erro
      return {
        adPasswordAgeLimitDays: 90,
        adInactiveUserLimitDays: 180,
        adMaxPrivilegedGroupMembers: 5,
        adComputerInactiveDays: 90,
      };
    }
  }

  /**
   * Atualiza uma configuração específica
   */
  static async updateSetting(key: string, value: any, userId: string): Promise<void> {
    await storage.setSetting(key, value, userId);
  }
}

export const settingsService = SettingsService;