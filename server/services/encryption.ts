import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits é o tamanho ideal para AES-GCM
const TAG_LENGTH = 16; // 128 bits para auth tag
const KEY_LENGTH = 32; // 256 bits para AES-256

// Get KEK from environment or generate one for development
function getKEK(): Buffer {
  const kekHex = process.env.ENCRYPTION_KEK;
  
  // Em produção, a chave DEVE estar configurada
  if (process.env.NODE_ENV === 'production' && !kekHex) {
    throw new Error('ENCRYPTION_KEK must be set in production environment');
  }
  
  if (kekHex) {
    const kek = Buffer.from(kekHex, 'hex');
    if (kek.length !== KEY_LENGTH) {
      throw new Error(`ENCRYPTION_KEK must be ${KEY_LENGTH * 2} hex characters (${KEY_LENGTH} bytes)`);
    }
    return kek;
  }
  
  // Para desenvolvimento, usar chave derivada (NOT for production!)
  console.warn('Using development encryption key. Set ENCRYPTION_KEK for production!');
  return crypto.scryptSync('samureye-dev-key', 'salt', KEY_LENGTH);
}

export class EncryptionService {
  private kek: Buffer;

  constructor() {
    this.kek = getKEK();
  }

  /**
   * Encrypts a credential using DEK (Data Encryption Key) approach
   * 1. Generate random DEK
   * 2. Encrypt secret with DEK using AES-256-GCM
   * 3. Encrypt DEK with KEK (Key Encryption Key) using AES-256-GCM
   */
  encryptCredential(secret: string): { secretEncrypted: string; dekEncrypted: string } {
    try {
      // Generate random DEK
      const dek = crypto.randomBytes(KEY_LENGTH);
      
      // Encrypt secret with DEK
      const secretResult = this.encryptData(secret, dek, 'samureye-credential');
      const secretEncrypted = secretResult.encrypted;
      
      // Encrypt DEK with KEK
      const dekResult = this.encryptData(dek.toString('hex'), this.kek, 'samureye-dek');
      const dekEncrypted = dekResult.encrypted;
      
      return { secretEncrypted, dekEncrypted };
    } catch (error) {
      throw new Error(`Falha ao criptografar credencial: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  /**
   * Decrypts a credential
   */
  decryptCredential(secretEncrypted: string, dekEncrypted: string): string {
    try {
      // Decrypt DEK with KEK
      const dekHex = this.decryptData(dekEncrypted, this.kek, 'samureye-dek');
      const dek = Buffer.from(dekHex, 'hex');
      
      if (dek.length !== KEY_LENGTH) {
        throw new Error('DEK inválida após descriptografia');
      }
      
      // Decrypt secret with DEK
      const secret = this.decryptData(secretEncrypted, dek, 'samureye-credential');
      
      return secret;
    } catch (error) {
      throw new Error(`Falha ao descriptografar credencial: ${error instanceof Error ? error.message : 'Erro desconhecido'}`);
    }
  }

  /**
   * Validates that a credential can be decrypted (for testing)
   */
  validateCredential(secretEncrypted: string, dekEncrypted: string): boolean {
    try {
      this.decryptCredential(secretEncrypted, dekEncrypted);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Internal method to encrypt data using AES-256-GCM
   */
  private encryptData(data: string, key: Buffer, aad: string): { encrypted: string } {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Set Additional Authenticated Data
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    
    // Encrypt the data
    let ciphertext = cipher.update(data, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    
    // Get authentication tag
    const authTag = cipher.getAuthTag();
    
    // Combine IV + AuthTag + Ciphertext
    const combined = Buffer.concat([iv, authTag, ciphertext]);
    
    return {
      encrypted: combined.toString('base64')
    };
  }

  /**
   * Internal method to decrypt data using AES-256-GCM
   */
  private decryptData(encryptedBase64: string, key: Buffer, aad: string): string {
    const combined = Buffer.from(encryptedBase64, 'base64');
    
    if (combined.length < IV_LENGTH + TAG_LENGTH) {
      throw new Error('Dados criptografados são muito curtos');
    }
    
    // Extract components
    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
    const ciphertext = combined.subarray(IV_LENGTH + TAG_LENGTH);
    
    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    
    // Set Additional Authenticated Data
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    
    // Set authentication tag (MUST be called after setAAD)
    decipher.setAuthTag(authTag);
    
    // Decrypt
    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Utility method to generate a new KEK for production use
   */
  static generateKEK(): string {
    return crypto.randomBytes(KEY_LENGTH).toString('hex');
  }

  /**
   * Utility method to validate KEK format
   */
  static validateKEK(kekHex: string): boolean {
    try {
      const kek = Buffer.from(kekHex, 'hex');
      return kek.length === KEY_LENGTH;
    } catch {
      return false;
    }
  }
}

export const encryptionService = new EncryptionService();