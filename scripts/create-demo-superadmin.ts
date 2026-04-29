if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL não definida. Execute com DATABASE_URL=... npx tsx scripts/create-demo-superadmin.ts");
  process.exit(1);
}

/**
 * Creates admin@samureye.local — demo superadmin who can see all leads.
 * Run: DATABASE_URL=... npx tsx scripts/create-demo-superadmin.ts
 * Idempotent — exits 0 if user already exists.
 */
import bcrypt from "bcryptjs";
import { pool } from "../server/db";

const email = "admin@samureye.local";
const password = "Admin@Demo2026!";

const client = await pool.connect();
try {
  const existing = await client.query(
    "SELECT id FROM users WHERE email = $1 LIMIT 1",
    [email],
  );
  if (existing.rows.length > 0) {
    console.log(`Superadmin ${email} já existe.`);
    process.exit(0);
  }

  const hash = await bcrypt.hash(password, 12);
  await client.query(
    `INSERT INTO users (email, first_name, last_name, role, password_hash, must_change_password)
     VALUES ($1, 'Demo', 'Superadmin', 'global_administrator', $2, true)`,
    [email, hash],
  );
  console.log(`Superadmin ${email} criado com senha: ${password}`);
} finally {
  client.release();
  await pool.end();
}
