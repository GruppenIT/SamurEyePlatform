// REDIGIDO PARA DEPOSITO INPI (sem segredos)
// Servico de criptografia - modelo DEK/KEK com AES-256-GCM
// Protege credenciais armazenadas no banco de dados

import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;  // 96 bits - tamanho ideal para AES-GCM
const TAG_LENGTH = 16;  // 128 bits para auth tag
const KEY_LENGTH = 32;  // 256 bits para AES-256

// Obtem KEK (Key Encryption Key) do ambiente
function getKEK(): Buffer {
  const kekHex = process.env.ENCRYPTION_KEK;
  if (process.env.NODE_ENV === 'production' && !kekHex) {
    throw new Error('ENCRYPTION_KEK must be set in production environment');
  }
  if (kekHex) {
    const kek = Buffer.from(kekHex, 'hex');
    if (kek.length !== KEY_LENGTH) {
      throw new Error(`ENCRYPTION_KEK must be ${KEY_LENGTH * 2} hex characters`);
    }
    return kek;
  }
  // Chave de desenvolvimento (NAO usar em producao)
  return crypto.scryptSync('REDACTED_DEV_KEY', 'salt', KEY_LENGTH);
}

export class EncryptionService {
  private kek: Buffer;

  constructor() {
    this.kek = getKEK();
  }

  /**
   * Criptografa uma credencial usando abordagem DEK:
   * 1. Gera DEK aleatoria
   * 2. Criptografa segredo com DEK (AES-256-GCM)
   * 3. Criptografa DEK com KEK (AES-256-GCM)
   */
  encryptCredential(secret: string): { secretEncrypted: string; dekEncrypted: string } {
    const dek = crypto.randomBytes(KEY_LENGTH);
    const secretResult = this.encryptData(secret, dek, 'samureye-credential');
    const secretEncrypted = secretResult.encrypted;
    const dekResult = this.encryptData(dek.toString('hex'), this.kek, 'samureye-dek');
    const dekEncrypted = dekResult.encrypted;
    return { secretEncrypted, dekEncrypted };
  }

  /**
   * Descriptografa uma credencial:
   * 1. Descriptografa DEK com KEK
   * 2. Descriptografa segredo com DEK
   */
  decryptCredential(secretEncrypted: string, dekEncrypted: string): string {
    const dekHex = this.decryptData(dekEncrypted, this.kek, 'samureye-dek');
    const dek = Buffer.from(dekHex, 'hex');
    return this.decryptData(secretEncrypted, dek, 'samureye-credential');
  }

  private encryptData(data: string, key: Buffer, aad: string): { encrypted: string } {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    cipher.setAAD(Buffer.from(aad));
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return { encrypted: combined.toString('base64') };
  }

  private decryptData(encryptedBase64: string, key: Buffer, aad: string): string {
    const combined = Buffer.from(encryptedBase64, 'base64');
    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const encrypted = combined.subarray(IV_LENGTH + TAG_LENGTH);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  }
}
