import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

export function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

export function verifyPassword(password, storedHash, salt) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

export async function openDb() {
  return open({
    filename: process.env.DATABASE_PATH || './licenses.db',
    driver: sqlite3.Database
  });
}

export async function initDb() {
  const db = await openDb();

  // Tabela de Licenças Otimizada
  await db.exec(`
    CREATE TABLE IF NOT EXISTS licenses (
      uuid TEXT PRIMARY KEY,
      company_name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      valid_until TEXT,
      is_lifetime INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active'
    )
  `);

  // Migrações dinâmicas para tabelas existentes
  const columns = await db.all("PRAGMA table_info(licenses)");
  const hasLifetime = columns.some(col => col.name === 'is_lifetime');
  if (!hasLifetime) {
    await db.exec("ALTER TABLE licenses ADD COLUMN is_lifetime INTEGER DEFAULT 0");
  }

  const hasStatus = columns.some(col => col.name === 'status');
  if (!hasStatus) {
    await db.exec("ALTER TABLE licenses ADD COLUMN status TEXT DEFAULT 'active'");
  }

  const hasApiKey = columns.some(col => col.name === 'api_key');
  if (!hasApiKey) {
    await db.exec("ALTER TABLE licenses ADD COLUMN api_key TEXT");
  }

  const hasCreatedByLic = columns.some(col => col.name === 'created_by');
  if (!hasCreatedByLic) {
    await db.exec("ALTER TABLE licenses ADD COLUMN created_by TEXT");
  }

  const hasHwid = columns.some(col => col.name === 'hwid');
  if (!hasHwid) {
    await db.exec("ALTER TABLE licenses ADD COLUMN hwid TEXT");
  }

  const hasHwidBoundAt = columns.some(col => col.name === 'hwid_bound_at');
  if (!hasHwidBoundAt) {
    await db.exec("ALTER TABLE licenses ADD COLUMN hwid_bound_at TEXT");
  }

  // Backfill de API Key única para licenças legadas sem api_key
  const emptyKeyLicenses = await db.all("SELECT uuid FROM licenses WHERE api_key IS NULL OR api_key = ''");
  for (const lic of emptyKeyLicenses) {
    const newApiKey = crypto.randomBytes(24).toString('hex');
    await db.run("UPDATE licenses SET api_key = ? WHERE uuid = ?", [newApiKey, lic.uuid]);
  }

  // Tabela de Usuários Administrativos
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      created_at TEXT NOT NULL
    )
  `);

  const userCols = await db.all("PRAGMA table_info(users)");
  const hasRole = userCols.some(col => col.name === 'role');
  if (!hasRole) {
    await db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'");
  }

  const hasEmail = userCols.some(col => col.name === 'email');
  if (!hasEmail) {
    await db.exec("ALTER TABLE users ADD COLUMN email TEXT");
  }

  const hasName = userCols.some(col => col.name === 'name');
  if (!hasName) {
    await db.exec("ALTER TABLE users ADD COLUMN name TEXT");
  }

  const hasMfaSecret = userCols.some(col => col.name === 'mfa_secret');
  if (!hasMfaSecret) {
    await db.exec("ALTER TABLE users ADD COLUMN mfa_secret TEXT");
  }

  const hasMfaEnabled = userCols.some(col => col.name === 'mfa_enabled');
  if (!hasMfaEnabled) {
    await db.exec("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0");
  }

  // Usuário inicial 'admin' se a tabela estiver vazia
  const userCount = await db.get('SELECT COUNT(*) as count FROM users');
  if (userCount.count === 0) {
    const { hash, salt } = hashPassword('admin123');
    const createdAt = new Date().toISOString();
    await db.run(
      'INSERT INTO users (username, email, name, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ['admin', 'admin@local', 'Administrador Geral', hash, salt, 'admin', createdAt]
    );
    console.log('[DB Initializer] Usuário padrão criado -> Usuário: admin | Senha: admin123 | Perfil: admin');
  }

  await db.run("UPDATE users SET name = 'Administrador Geral' WHERE username = 'admin' AND (name IS NULL OR name = '')");
  await db.run("UPDATE users SET email = 'admin@local' WHERE username = 'admin' AND (email IS NULL OR email = '')");

  // Tabela de Logs de Acesso / Tentativas Não Autorizadas
  await db.exec(`
    CREATE TABLE IF NOT EXISTS access_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      uuid TEXT,
      api_key_used TEXT,
      reason TEXT,
      endpoint TEXT,
      method TEXT,
      user_agent TEXT,
      status_code INTEGER,
      created_at TEXT NOT NULL
    )
  `);

  // Tabela de IPs Bloqueados (Blacklist)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      blocked_by TEXT,
      created_at TEXT NOT NULL
    )
  `);

  const blockedCols = await db.all("PRAGMA table_info(blocked_ips)");
  const hasStatusBlocked = blockedCols.some(col => col.name === 'status');
  if (!hasStatusBlocked) {
    await db.exec("ALTER TABLE blocked_ips ADD COLUMN status TEXT DEFAULT 'blocked'");
  }

  const hasUnblockedBy = blockedCols.some(col => col.name === 'unblocked_by');
  if (!hasUnblockedBy) {
    await db.exec("ALTER TABLE blocked_ips ADD COLUMN unblocked_by TEXT");
  }

  const hasUnblockedAt = blockedCols.some(col => col.name === 'unblocked_at');
  if (!hasUnblockedAt) {
    await db.exec("ALTER TABLE blocked_ips ADD COLUMN unblocked_at TEXT");
  }

  // Tabela de Configurações Globais do Sistema
  await db.exec(`
    CREATE TABLE IF NOT EXISTS system_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

  await db.run("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('require_mfa_all', '0')");

  return db;
}

export function validatePasswordStrength(password) {
  if (!password || password.length < 8) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[@$!%*?&_#^()\-+=]/.test(password);
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

export async function logAccessAttempt({ ip, uuid, apiKeyUsed, reason, endpoint, method, userAgent, statusCode }) {
  try {
    const db = await openDb();
    const createdAt = new Date().toISOString();
    await db.run(
      `INSERT INTO access_logs (ip, uuid, api_key_used, reason, endpoint, method, user_agent, status_code, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        ip || 'desconhecido',
        uuid || null,
        apiKeyUsed ? (apiKeyUsed.length > 16 ? apiKeyUsed.substring(0, 10) + '...' : apiKeyUsed) : null,
        reason || 'Acesso negado',
        endpoint || '/api/validate',
        method || 'POST',
        userAgent || null,
        statusCode || 401,
        createdAt
      ]
    );
  } catch (err) {
    console.error('[DB Log Error] Falha ao registrar log de acesso no banco:', err.message);
  }
}

export async function isIpBlocked(ip) {
  if (!ip || ip === 'desconhecido' || ip === '127.0.0.1' || ip === '::1') return false;
  try {
    const db = await openDb();
    const record = await db.get("SELECT ip FROM blocked_ips WHERE ip = ? AND (status IS NULL OR status = 'blocked')", [ip]);
    return !!record;
  } catch (err) {
    return false;
  }
}

export async function blockIp(ip, reason = 'Bloqueio manual via Painel', blockedBy = 'sistema') {
  if (!ip || ip === 'desconhecido' || ip === '127.0.0.1' || ip === '::1') return;
  const db = await openDb();
  const createdAt = new Date().toISOString();

  const existing = await db.get("SELECT ip FROM blocked_ips WHERE ip = ?", [ip]);
  if (existing) {
    await db.run(
      `UPDATE blocked_ips 
       SET reason = ?, blocked_by = ?, created_at = ?, status = 'blocked', unblocked_by = NULL, unblocked_at = NULL 
       WHERE ip = ?`,
      [reason, blockedBy, createdAt, ip]
    );
  } else {
    await db.run(
      'INSERT INTO blocked_ips (ip, reason, blocked_by, created_at, status) VALUES (?, ?, ?, ?, "blocked")',
      [ip, reason, blockedBy, createdAt]
    );
  }
}

export async function unblockIp(ip, unblockedBy = 'sistema') {
  const db = await openDb();
  const unblockedAt = new Date().toISOString();
  await db.run(
    "UPDATE blocked_ips SET status = 'unblocked', unblocked_by = ?, unblocked_at = ? WHERE ip = ?",
    [unblockedBy, unblockedAt, ip]
  );
}

export async function getBlockedIps() {
  const db = await openDb();
  return db.all('SELECT * FROM blocked_ips ORDER BY created_at DESC');
}

export async function getUsers() {
  const db = await openDb();
  return db.all('SELECT id, username, email, name, role, mfa_enabled, created_at FROM users ORDER BY created_at DESC');
}

export async function createUser({ name, email, password, role = 'user' }) {
  const db = await openDb();
  const allowedRoles = ['admin', 'operator', 'user'];
  const finalRole = allowedRoles.includes(role) ? role : 'user';
  const cleanEmail = email.trim().toLowerCase();
  const cleanName = name.trim();
  const { hash, salt } = hashPassword(password);
  const createdAt = new Date().toISOString();
  await db.run(
    'INSERT INTO users (username, email, name, password_hash, salt, role, mfa_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
    [cleanEmail, cleanEmail, cleanName, hash, salt, finalRole, createdAt]
  );
  return db.get('SELECT id, username, email, name, role, mfa_enabled, created_at FROM users WHERE email = ?', [cleanEmail]);
}

export async function deleteUser(id) {
  const db = await openDb();
  const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) throw new Error('Usuário não encontrado.');
  if (user.username === 'admin') throw new Error('O usuário admin padrão não pode ser excluído.');
  await db.run('DELETE FROM users WHERE id = ?', [id]);
}

export async function updateUserByAdmin({ id, name, email, role, password, resetMfa }) {
  const db = await openDb();
  const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) throw new Error('Usuário não encontrado.');

  const allowedRoles = ['admin', 'operator', 'user'];
  const finalRole = allowedRoles.includes(role) ? role : (user.role || 'user');
  const cleanEmail = email ? email.trim().toLowerCase() : user.email;
  const cleanName = name ? name.trim() : user.name;

  let query = 'UPDATE users SET name = ?, email = ?, username = ?, role = ?';
  let params = [cleanName, cleanEmail, cleanEmail, finalRole];

  if (password && password.trim() !== '') {
    const { hash, salt } = hashPassword(password);
    query += ', password_hash = ?, salt = ?';
    params.push(hash, salt);
  }

  if (resetMfa) {
    query += ', mfa_enabled = 0, mfa_secret = NULL';
  }

  query += ' WHERE id = ?';
  params.push(id);

  await db.run(query, params);

  return db.get('SELECT id, username, email, name, role, mfa_enabled, created_at FROM users WHERE id = ?', [id]);
}

export async function enableUserMfa(id, secret) {
  const db = await openDb();
  await db.run('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?', [secret, id]);
}

export async function disableUserMfa(id) {
  const db = await openDb();
  await db.run('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?', [id]);
}

export async function getSystemSettings() {
  const db = await openDb();
  const row = await db.get("SELECT value FROM system_settings WHERE key = 'require_mfa_all'");
  return {
    require_mfa_all: row ? (row.value === '1' || row.value === 'true') : false
  };
}

export async function updateSystemSettings({ require_mfa_all }) {
  const db = await openDb();
  const valStr = require_mfa_all ? '1' : '0';
  await db.run("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('require_mfa_all', ?)", [valStr]);
  return getSystemSettings();
}
