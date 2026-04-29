import type { Express } from "express";
import { isAuthenticatedWithPasswordCheck } from "../localAuth";
import { storage } from "../storage";
import { createLogger } from '../lib/logger';
import bcrypt from "bcryptjs";
import { randomBytes } from "crypto";

const log = createLogger('routes:demo');

// Simple in-memory rate limiter for demo registration (5 req/IP/hour)
const registerAttempts = new Map<string, number[]>();
function isDemoRegisterRateLimited(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const maxAttempts = 5;
  const attempts = (registerAttempts.get(ip) ?? []).filter(t => now - t < windowMs);
  if (attempts.length >= maxAttempts) return true;
  registerAttempts.set(ip, [...attempts, now]);
  return false;
}

function generateDemoPassword(): string {
  // Memorable format: Samu-XXXX (no ambiguous chars: I, O, 0, 1)
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(4);
  const code = Array.from(bytes).map(b => chars[b % chars.length]).join('');
  return `Samu-${code}`;
}

function validateCnpj(cnpj: string): boolean {
  const d = cnpj.replace(/\D/g, '');
  if (d.length !== 14 || /^(\d)\1+$/.test(d)) return false;
  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const calc = (digits: string, weights: number[]) => {
    const sum = weights.reduce((acc, w, i) => acc + parseInt(digits[i]) * w, 0);
    const rem = sum % 11;
    return rem < 2 ? 0 : 11 - rem;
  };
  return calc(d, w1) === parseInt(d[12]) && calc(d, w2) === parseInt(d[13]);
}

export function registerDemoRoutes(app: Express) {
  // POST /api/demo/register — creates a demo lead user with 24h access
  app.post('/api/demo/register', async (req, res) => {
    if (process.env.DEMO_MODE !== 'true') {
      return res.status(404).json({ message: 'Not found' });
    }

    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    if (isDemoRegisterRateLimited(clientIP)) {
      return res.status(429).json({ message: 'Muitas solicitações. Tente novamente em 1 hora.' });
    }

    const { name, company, cnpj, email } = req.body;

    // Basic validation
    if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 120) {
      return res.status(400).json({ message: 'Nome inválido.' });
    }
    if (!company || typeof company !== 'string' || company.trim().length < 2 || company.trim().length > 120) {
      return res.status(400).json({ message: 'Empresa inválida.' });
    }
    if (!email || typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Email inválido.' });
    }
    if (!cnpj || !validateCnpj(cnpj)) {
      return res.status(400).json({ message: 'CNPJ inválido.' });
    }

    try {
      // Check duplicate
      const existing = await storage.getUserByEmail(email.toLowerCase().trim());
      if (existing) {
        return res.status(409).json({
          error: 'already_registered',
          message: 'Este e-mail já está cadastrado. Para mais informações, entre em contato com comercial@gruppen.com.br',
        });
      }

      const cnpjDigits = cnpj.replace(/\D/g, '');

      const nameParts = name.trim().split(/\s+/);
      const firstName = nameParts[0];
      const lastName = nameParts.slice(1).join(' ') || '-';

      const password = generateDemoPassword();
      const passwordHash = await bcrypt.hash(password, 12);
      const demoExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await storage.createDemoLead({
        email: email.toLowerCase().trim(),
        passwordHash,
        firstName,
        lastName,
        company: company.trim(),
        cnpj: cnpj.replace(/\D/g, ''),
        demoExpiresAt,
      });

      log.info({ email, company: company.trim().slice(0, 120) }, 'demo lead registered');

      res.json({
        email: email.toLowerCase().trim(),
        password,
        expiresAt: demoExpiresAt.toISOString(),
      });
    } catch (err) {
      log.error({ err }, 'failed to create demo lead');
      res.status(500).json({ message: 'Erro ao criar usuário. Tente novamente.' });
    }
  });

  // GET /api/demo/leads — only admin@samureye.local
  app.get('/api/demo/leads', isAuthenticatedWithPasswordCheck, async (req: any, res) => {
    if (process.env.DEMO_MODE !== 'true') {
      return res.status(404).json({ message: 'Not found' });
    }
    if (req.user?.email !== 'admin@samureye.local') {
      return res.status(403).json({ message: 'Acesso negado.' });
    }

    const allUsers = await storage.getAllUsers();
    const leads = allUsers
      .filter(u => u.isDemoLead)
      .map(({ passwordHash, mfaSecretEncrypted, mfaSecretDek, mfaBackupCodes, ...u }) => u);

    res.json(leads);
  });
}
