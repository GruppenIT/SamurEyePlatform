/**
 * Creates the demo admin user used by the install-demo.sh installer.
 * Run: DATABASE_URL=... npx tsx scripts/create-demo-admin.ts
 */
import bcrypt from "bcryptjs";
import { pool } from "../server/db";

const email = process.env.ADMIN_EMAIL ?? "demo@samureye.com.br";
const password = process.env.ADMIN_PASSWORD ?? "Demo@2026!";

const client = await pool.connect();
try {
  const existing = await client.query(
    "SELECT id FROM users WHERE email = $1 LIMIT 1",
    [email],
  );
  if (existing.rows.length > 0) {
    console.log(`Admin ${email} já existe.`);
    process.exit(0);
  }

  const hash = await bcrypt.hash(password, 12);
  await client.query(
    `INSERT INTO users (id, email, name, role, password_hash, created_at)
     VALUES (gen_random_uuid(), $1, 'Demo Admin', 'global_administrator', $2, NOW())`,
    [email, hash],
  );
  console.log(`Admin ${email} criado.`);
} finally {
  client.release();
  await pool.end();
}
