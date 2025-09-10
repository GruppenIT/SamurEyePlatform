import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;

// Get KEK from environment or generate one for development
function getKEK(): Buffer {
  const kekHex = process.env.ENCRYPTION_KEK;
  if (kekHex) {
    return Buffer.from(kekHex, 'hex');
  }
  
  // For development, use a fixed key (NOT for production!)
  console.warn('Using development encryption key. Set ENCRYPTION_KEK for production!');
  return crypto.scryptSync('samureye-dev-key', 'salt', 32);
}

export class EncryptionService {
  private kek: Buffer;

  constructor() {
    this.kek = getKEK();
  }

  /**
   * Encrypts a credential using DEK (Data Encryption Key) approach
   * 1. Generate random DEK
   * 2. Encrypt secret with DEK
   * 3. Encrypt DEK with KEK (Key Encryption Key)
   */
  encryptCredential(secret: string): { secretEncrypted: string; dekEncrypted: string } {
    // Generate random DEK
    const dek = crypto.randomBytes(32);
    
    // Encrypt secret with DEK
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipher(ALGORITHM, dek);
    cipher.setAAD(Buffer.from('samureye-credential'));
    
    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    const secretEncrypted = Buffer.concat([
      iv,
      authTag,
      Buffer.from(encrypted, 'hex')
    ]).toString('base64');
    
    // Encrypt DEK with KEK
    const dekIv = crypto.randomBytes(IV_LENGTH);
    const dekCipher = crypto.createCipher(ALGORITHM, this.kek);
    dekCipher.setAAD(Buffer.from('samureye-dek'));
    
    let dekEncryptedHex = dekCipher.update(dek, undefined, 'hex');
    dekEncryptedHex += dekCipher.final('hex');
    const dekAuthTag = dekCipher.getAuthTag();
    
    const dekEncrypted = Buffer.concat([
      dekIv,
      dekAuthTag,
      Buffer.from(dekEncryptedHex, 'hex')
    ]).toString('base64');
    
    return { secretEncrypted, dekEncrypted };
  }

  /**
   * Decrypts a credential
   */
  decryptCredential(secretEncrypted: string, dekEncrypted: string): string {
    try {
      // Decrypt DEK with KEK
      const dekBuffer = Buffer.from(dekEncrypted, 'base64');
      const dekIv = dekBuffer.subarray(0, IV_LENGTH);
      const dekAuthTag = dekBuffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
      const dekCiphertext = dekBuffer.subarray(IV_LENGTH + TAG_LENGTH);
      
      const dekDecipher = crypto.createDecipher(ALGORITHM, this.kek);
      dekDecipher.setAuthTag(dekAuthTag);
      dekDecipher.setAAD(Buffer.from('samureye-dek'));
      
      let dekHex = dekDecipher.update(dekCiphertext, undefined, 'hex');
      dekHex += dekDecipher.final('hex');
      const dek = Buffer.from(dekHex, 'hex');
      const dekBuffer2 = Buffer.from(dek, 'hex');
      
      // Decrypt secret with DEK
      const secretBuffer = Buffer.from(secretEncrypted, 'base64');
      const iv = secretBuffer.subarray(0, IV_LENGTH);
      const authTag = secretBuffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
      const ciphertext = secretBuffer.subarray(IV_LENGTH + TAG_LENGTH);
      
      const decipher = crypto.createDecipher(ALGORITHM, dekBuffer2);
      decipher.setAuthTag(authTag);
      decipher.setAAD(Buffer.from('samureye-credential'));
      
      let decrypted = decipher.update(ciphertext, undefined, 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error('Falha ao descriptografar credencial');
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
}

export const encryptionService = new EncryptionService();
