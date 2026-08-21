import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';
import { openDb, hashPassword, verifyPassword, logAccessAttempt, isIpBlocked, blockIp, unblockIp, getBlockedIps, validatePasswordStrength, getUsers, createUser, deleteUser, updateUserByAdmin, enableUserMfa, disableUserMfa, getSystemSettings, updateSystemSettings } from './db.js';
import { generateAdminToken, authenticateAdminToken, requireRole } from './auth.js';
import dotenv from 'dotenv';

dotenv.config();

const router = express.Router();

// Rate Limiter para Login Admin (Máximo 15 tentativas por janela de 15 minutos por IP, ignorando acessos bem sucedidos)
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    const ip = getClientIp(req);
    await logAccessAttempt({
      ip,
      reason: '[Painel Web] Ataque de Força Bruta de Login (Rate Limit Excedido)',
      endpoint: req.originalUrl,
      method: req.method,
      userAgent: req.headers['x-user-agent'] || req.headers['user-agent'],
      statusCode: 429
    });
    return res.status(429).json({
      success: false,
      error: 'Muitas tentativas incorretas de login a partir deste IP. Por razões de segurança, tente novamente após 15 minutos.'
    });
  }
});

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || req.ip || 'desconhecido';
}

/**
 * Função Auxiliar de Validação do UUID e da X-API-Key
 */
async function processValidation(req) {
  const clientIp = getClientIp(req);

  // 0. Verificar se o IP está bloqueado na blacklist
  if (await isIpBlocked(clientIp)) {
    return {
      httpCode: 403,
      json: { status: 'error', valid: false, reason: 'Acesso negado. Endereço IP bloqueado pelo administrador.' }
    };
  }

  const uuid = req.body?.uuid || req.query?.uuid;
  const clientApiKey = req.headers['x-api-key'] || req.headers['api-key'] || req.query.api_key;

  // 1. Validação da presença do UUID
  if (!uuid) {
    return {
      httpCode: 400,
      json: { status: 'error', valid: false, reason: 'UUID não fornecido na requisição.' }
    };
  }

  // 2. Validação da presença da X-API-Key no cabeçalho ou parâmetro
  if (!clientApiKey) {
    return {
      httpCode: 401,
      json: { status: 'error', valid: false, reason: 'Acesso não autorizado. Cabeçalho X-API-Key ausente.' }
    };
  }

  try {
    const db = await openDb();
    const record = await db.get('SELECT * FROM licenses WHERE uuid = ?', [uuid]);

    // 3. Validação se a licença existe no banco de dados
    if (!record) {
      return {
        httpCode: 401,
        json: { status: 'error', valid: false, reason: 'Licença não encontrada.' }
      };
    }

    // 3. Validação estrita da X-API-Key única vinculada à licença
    if (!record.api_key || clientApiKey !== record.api_key) {
      return {
        httpCode: 401,
        json: { status: 'error', valid: false, reason: 'Acesso não autorizado. X-API-Key inválida para este UUID.' }
      };
    }

    if (record.status && record.status !== 'active') {
      return {
        httpCode: 400,
        json: { status: 'error', valid: false, reason: 'Licença desativada ou revogada.' }
      };
    }

    // 4. Validação e Vinculação de Hardware ID (HWID)
    const clientHwid = req.body?.hwid || req.headers['x-hwid'] || req.query?.hwid;

    if (!clientHwid || clientHwid.trim() === '') {
      return {
        httpCode: 401,
        json: { status: 'error', valid: false, reason: 'Acesso não autorizado. Hardware ID (HWID) não informado.' }
      };
    }

    const cleanHwid = clientHwid.trim();

    if (!record.hwid || record.hwid.trim() === '') {
      // Primeiro uso: Auto-vincula a máquina enviada no primeiro acesso
      const boundAt = new Date().toISOString();
      await db.run('UPDATE licenses SET hwid = ?, hwid_bound_at = ? WHERE uuid = ?', [cleanHwid, boundAt, record.uuid]);
      record.hwid = cleanHwid;
      record.hwid_bound_at = boundAt;
    } else {
      // Máquina já vinculada: Verificar se a requisição veio do mesmo HWID
      if (cleanHwid !== record.hwid) {
        return {
          httpCode: 401,
          json: { status: 'error', valid: false, reason: 'Acesso não autorizado. Esta licença está vinculada a outro computador/hardware.' }
        };
      }
    }

    // Se for vitalícia (is_lifetime === 1) ou valid_until for 'LIFETIME'
    if (record.is_lifetime === 1 || record.valid_until === 'LIFETIME') {
      return {
        httpCode: 200,
        json: {
          status: 'ok',
          valid: true,
          company_name: record.company_name,
          validUntil: 'LIFETIME',
          is_lifetime: true,
          uuid: record.uuid,
          hwid: record.hwid || null
        }
      };
    }

    // Validação de Data de Validade
    const now = new Date();
    const validUntil = new Date(record.valid_until);

    if (isNaN(validUntil.getTime()) || validUntil <= now) {
      return {
        httpCode: 400,
        json: {
          status: 'error',
          valid: false,
          reason: 'Licença expirada.',
          validUntil: record.valid_until
        }
      };
    }

    // Licença Válida!
    return {
      httpCode: 200,
      json: {
        status: 'ok',
        valid: true,
        company_name: record.company_name,
        validUntil: record.valid_until,
        is_lifetime: false,
        uuid: record.uuid,
        hwid: record.hwid || null
      }
    };

  } catch (error) {
    console.error('Erro no processamento da licença:', error);
    return {
      httpCode: 500,
      json: { status: 'error', valid: false, reason: 'Erro interno ao processar validação.' }
    };
  }
}

/**
 * ===================================================================
 *  ROTA DE HEALTH CHECK (Para HAProxy, pfSense e monitoramento GET)
 * ===================================================================
 */
async function handleHealthCheck(req, res) {
  try {
    const db = await openDb();
    await db.get('SELECT 1');
    return res.status(200).json({
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'Banco de dados ou serviço indisponível.',
      error: error.message
    });
  }
}

router.get('/health', handleHealthCheck);
router.get('/healthz', handleHealthCheck);
router.get('/api/health', handleHealthCheck);

/**
 * ===================================================================
 *  ROTA PÚBLICA DE VALIDAÇÃO (Para programas externos / executáveis)
 * ===================================================================
 */
async function handleValidation(req, res) {
  const result = await processValidation(req);
  if (result.httpCode !== 200) {
    logAccessAttempt({
      ip: getClientIp(req),
      uuid: req.body?.uuid || req.query?.uuid,
      apiKeyUsed: req.headers['x-api-key'] || req.headers['api-key'] || req.query?.api_key,
      reason: `[Validação API] ${result.json.reason}`, // Motivo interno detalhado gravado no SQLite para o Admin
      endpoint: req.originalUrl || req.path,
      method: req.method,
      userAgent: req.headers['user-agent'],
      statusCode: result.httpCode
    });

    // Resposta genérica sem expor o motivo ao cliente externo por segurança
    return res.status(401).json({
      status: 'error',
      valid: false,
      reason: 'Acesso não autorizado.'
    });
  }
  return res.status(result.httpCode).json(result.json);
}

router.post('/api/validate', handleValidation);
router.get('/api/validate', handleValidation);


/**
 * ===================================================================
 *  ROTAS DA API ADMINISTRATIVA (Protegidas por JWT, Rate Limit e MFA)
 * ===================================================================
 */

// Login de Usuário (E-mail para usuários comuns, Username para admin) com Proteção de Rate Limiting & MFA
router.post('/api/admin/login', loginRateLimiter, async (req, res) => {
  const loginInput = (req.body.login || req.body.username || req.body.email || 'admin').trim();
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, error: 'E-mail/Usuário e senha são obrigatórios.' });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE email = ? OR username = ?', [loginInput, loginInput]);

    if (!user) {
      await logAccessAttempt({
        ip: getClientIp(req),
        reason: '[Painel Web] Tentativa de Login Falhada (Usuário não encontrado)',
        endpoint: req.originalUrl,
        method: req.method,
        userAgent: req.headers['x-user-agent'] || req.headers['user-agent'],
        statusCode: 401
      });
      return res.status(401).json({ success: false, error: 'E-mail/Usuário ou senha incorretos.' });
    }

    const isValid = verifyPassword(password, user.password_hash, user.salt);

    if (isValid) {
      const role = user.role || 'admin';
      const displayName = user.name || user.username || user.email;
      const isMfaActive = Number(user.mfa_enabled) === 1;
      const sysSettings = await getSystemSettings();

      const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-padrao-super-segura-123!';

      // Caso 1: Usuário já possui MFA ativado (2FA TOTP) -> Exigir 2ª etapa
      if (isMfaActive) {
        const mfaPendingToken = jwt.sign(
          { userId: user.id, username: user.username || user.email, name: displayName, role, pendingMfa: true },
          JWT_SECRET,
          { expiresIn: '5m' }
        );
        return res.json({
          success: true,
          mfaRequired: true,
          mfaToken: mfaPendingToken,
          message: 'Autenticação em duas etapas (MFA) necessária.'
        });
      }

      // Caso 2: Política global de MFA Obrigatório está ativada e o usuário ainda NÃO tem MFA -> Redirecionar para onboarding de MFA
      if (sysSettings.require_mfa_all && !isMfaActive) {
        const mfaPendingToken = jwt.sign(
          { userId: user.id, username: user.username || user.email, name: displayName, role, pendingMfaSetup: true },
          JWT_SECRET,
          { expiresIn: '10m' }
        );
        return res.json({
          success: true,
          mfaSetupRequired: true,
          mfaToken: mfaPendingToken,
          message: 'A política do serviço exige o cadastro da Autenticação em Duas Etapas (MFA).'
        });
      }

      // Caso 3: Login normal sem exigência de MFA
      const token = generateAdminToken(user.username || user.email, displayName, role);
      return res.json({ success: true, mfaRequired: false, token, username: user.username || user.email, name: displayName, role });
    } else {
      await logAccessAttempt({
        ip: getClientIp(req),
        reason: '[Painel Web] Tentativa de Login Falhada (Senha Incorreta)',
        endpoint: req.originalUrl,
        method: req.method,
        userAgent: req.headers['x-user-agent'] || req.headers['user-agent'],
        statusCode: 401
      });
      return res.status(401).json({ success: false, error: 'E-mail/Usuário ou senha incorretos.' });
    }
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Erro ao autenticar: ' + error.message });
  }
});

// Verificação do Código TOTP no Login (Etapa 2 do Login para quem já tem MFA)
router.post('/api/admin/mfa/verify-login', loginRateLimiter, async (req, res) => {
  const { mfaToken, totpToken } = req.body;

  if (!mfaToken || !totpToken) {
    return res.status(400).json({ success: false, error: 'Token de sessão e código de 6 dígitos são obrigatórios.' });
  }

  const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-padrao-super-segura-123!';

  try {
    const decoded = jwt.verify(mfaToken, JWT_SECRET);
    if (!decoded.pendingMfa || !decoded.userId) {
      return res.status(401).json({ success: false, error: 'Sessão de verificação MFA inválida.' });
    }

    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.userId]);

    if (!user || Number(user.mfa_enabled) !== 1 || !user.mfa_secret) {
      return res.status(400).json({ success: false, error: 'Autenticação MFA não configurada para este usuário.' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: 'base32',
      token: totpToken.trim(),
      window: 1
    });

    if (!verified) {
      return res.status(401).json({ success: false, error: 'Código de autenticação de 6 dígitos inválido ou expirado.' });
    }

    const role = user.role || 'admin';
    const displayName = user.name || user.username || user.email;
    const token = generateAdminToken(user.username || user.email, displayName, role);

    return res.json({ success: true, token, username: user.username || user.email, name: displayName, role });
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Sessão de login expirada ou código MFA inválido.' });
  }
});

// Gerar QR Code para Cadastro de MFA Durante o Login (Onboarding Obrigatório)
router.post('/api/admin/mfa/setup-login', loginRateLimiter, async (req, res) => {
  const { mfaToken } = req.body;

  if (!mfaToken) {
    return res.status(400).json({ success: false, error: 'Token de sessão é obrigatório.' });
  }

  const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-padrao-super-segura-123!';

  try {
    const decoded = jwt.verify(mfaToken, JWT_SECRET);
    if (!decoded.pendingMfaSetup || !decoded.userId) {
      return res.status(401).json({ success: false, error: 'Sessão de cadastro de MFA inválida.' });
    }

    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.userId]);

    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuário não encontrado.' });
    }

    const secret = speakeasy.generateSecret({
      length: 20,
      name: `TIMR Licensing (${user.username || user.email})`,
      issuer: 'TIMR Licensing'
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Sessão de login expirada.' });
  }
});

// Confirmar Código de 6 Dígitos e Ativar MFA Durante o Login (Conclui Login)
router.post('/api/admin/mfa/enable-login', loginRateLimiter, async (req, res) => {
  const { mfaToken, secret, totpToken } = req.body;

  if (!mfaToken || !secret || !totpToken) {
    return res.status(400).json({ success: false, error: 'Token de sessão, secret e código de 6 dígitos são obrigatórios.' });
  }

  const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-padrao-super-segura-123!';

  try {
    const decoded = jwt.verify(mfaToken, JWT_SECRET);
    if (!decoded.pendingMfaSetup || !decoded.userId) {
      return res.status(401).json({ success: false, error: 'Sessão de cadastro de MFA inválida.' });
    }

    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: totpToken.trim(),
      window: 1
    });

    if (!verified) {
      return res.status(400).json({ success: false, error: 'Código de confirmação de 6 dígitos inválido. Verifique o horário do celular.' });
    }

    await enableUserMfa(decoded.userId, secret);

    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.userId]);

    const role = user.role || 'admin';
    const displayName = user.name || user.username || user.email;
    const token = generateAdminToken(user.username || user.email, displayName, role);

    return res.json({
      success: true,
      token,
      username: user.username || user.email,
      name: displayName,
      role,
      message: 'MFA ativado com sucesso! Seja bem-vindo ao sistema.'
    });
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Sessão expirada ou erro ao ativar MFA.' });
  }
});

// Rotas de Gerenciamento de MFA no Perfil do Usuário
router.get('/api/admin/mfa/status', authenticateAdminToken, async (req, res) => {
  try {
    const db = await openDb();
    const user = await db.get('SELECT mfa_enabled FROM users WHERE username = ? OR email = ?', [req.admin.username, req.admin.username]);
    return res.json({ success: true, mfaEnabled: user ? (Number(user.mfa_enabled) === 1) : false });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/api/admin/mfa/setup', authenticateAdminToken, async (req, res) => {
  try {
    const userEmail = req.admin.username;
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `TIMR Licensing (${userEmail})`,
      issuer: 'TIMR Licensing'
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Erro ao gerar QR Code do MFA: ' + error.message });
  }
});

router.post('/api/admin/mfa/enable', authenticateAdminToken, async (req, res) => {
  const { secret, token } = req.body;

  if (!secret || !token) {
    return res.status(400).json({ success: false, error: 'Secret e código do autenticador são obrigatórios.' });
  }

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: token.trim(),
    window: 1
  });

  if (!verified) {
    return res.status(400).json({ success: false, error: 'Código de confirmação de 6 dígitos inválido. Verifique se o horário do seu celular está correto.' });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT id FROM users WHERE username = ? OR email = ?', [req.admin.username, req.admin.username]);
    await enableUserMfa(user.id, secret);
    return res.json({ success: true, message: 'Autenticação em Duas Etapas (MFA) ativada com sucesso!' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/api/admin/mfa/disable', authenticateAdminToken, async (req, res) => {
  const { currentPassword } = req.body;

  if (!currentPassword) {
    return res.status(400).json({ success: false, error: 'Digite a sua senha atual para desativar o MFA.' });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', [req.admin.username, req.admin.username]);

    if (!user || !verifyPassword(currentPassword, user.password_hash, user.salt)) {
      return res.status(401).json({ success: false, error: 'Senha atual incorreta.' });
    }

    await disableUserMfa(user.id);
    return res.json({ success: true, message: 'Autenticação em Duas Etapas (MFA) desativada.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Alterar Senha do Próprio Usuário Logado (Perfil - Todos os Perfis)
router.post('/api/admin/change-password', authenticateAdminToken, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const username = req.admin.username;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ success: false, error: 'Senha atual, nova senha e confirmação são obrigatórias.' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ success: false, error: 'A nova senha e a confirmação de senha não coincidem.' });
  }

  if (!validatePasswordStrength(newPassword)) {
    return res.status(400).json({
      success: false,
      error: 'A nova senha deve possuir no mínimo 8 caracteres, contendo pelo menos 1 letra maiúscula, 1 letra minúscula, 1 número e 1 caractere especial (@$!%*?&_#^()-+=).'
    });
  }

  try {
    const db = await openDb();
    const user = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);

    if (!user || !verifyPassword(currentPassword, user.password_hash, user.salt)) {
      return res.status(401).json({ success: false, error: 'Senha atual incorreta.' });
    }

    const { hash, salt } = hashPassword(newPassword);
    await db.run('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?', [hash, salt, user.id]);

    return res.json({ success: true, message: 'Senha alterada com sucesso.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * ===================================================================
 *  GESTÃO DE USUÁRIOS (Exclusivo para perfil Administrador - Admin)
 * ===================================================================
 */

// Listar todos os usuários
router.get('/api/admin/users', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  try {
    const list = await getUsers();
    return res.json({ success: true, users: list });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Criar novo usuário (com Nome de Visualização e E-mail de Login)
router.post('/api/admin/users', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  const { name, email, password, confirmPassword, role } = req.body;

  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).json({ success: false, error: 'Nome de exibição, E-mail de login, senha e confirmação são obrigatórios.' });
  }

  const emailRegex = /\S+@\S+\.\S+/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, error: 'Por favor, informe um e-mail válido para o usuário.' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, error: 'A senha e a confirmação de senha não coincidem.' });
  }

  if (!validatePasswordStrength(password)) {
    return res.status(400).json({
      success: false,
      error: 'A senha deve possuir no mínimo 8 caracteres, contendo pelo menos 1 letra maiúscula, 1 letra minúscula, 1 número e 1 caractere especial (@$!%*?&_#^()-+=).'
    });
  }

  try {
    const newUser = await createUser({ name, email, password, role: role || 'user' });
    return res.status(201).json({ success: true, user: newUser });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ success: false, error: 'Este e-mail já está cadastrado no sistema.' });
    }
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Editar usuário (Apenas Admin)
router.put('/api/admin/users/:id', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  const { id } = req.params;
  const { name, email, role, newPassword } = req.body;

  if (newPassword && newPassword.trim() !== '') {
    if (!validatePasswordStrength(newPassword)) {
      return res.status(400).json({
        success: false,
        error: 'A nova senha deve possuir no mínimo 8 caracteres, contendo pelo menos 1 letra maiúscula, 1 letra minúscula, 1 número e 1 caractere especial (@$!%*?&_#^()-+=).'
      });
    }
  }

  try {
    const updatedUser = await updateUserByAdmin({ id, name, email, role, password: newPassword });
    return res.json({ success: true, user: updatedUser });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
});

// Excluir usuário
router.delete('/api/admin/users/:id', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  const { id } = req.params;
  try {
    await deleteUser(id);
    return res.json({ success: true, message: 'Usuário excluído com sucesso.' });
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
});

/**
 * ===================================================================
 *  GERENCIAMENTO DE LICENÇAS (Admin, Operador, Usuário Leitor)
 * ===================================================================
 */

// Listar todas as licenças (Admin, Operador, Usuário)
router.get('/api/admin/licenses', authenticateAdminToken, requireRole(['admin', 'operator', 'user']), async (req, res) => {
  try {
    const db = await openDb();
    const licenses = await db.all('SELECT * FROM licenses ORDER BY created_at DESC');
    return res.json({ success: true, licenses });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Criar nova licença (Admin, Operador)
router.post('/api/admin/licenses', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  const { company_name, valid_until, is_lifetime, status, api_key } = req.body;
  const uuid = uuidv4();
  const apiKey = (api_key && api_key.trim() !== '') ? api_key.trim() : crypto.randomBytes(24).toString('hex');
  const created_at = new Date().toISOString();
  const created_by = req.admin.name || req.admin.username || 'admin';

  const isLifetimeNum = (is_lifetime === true || is_lifetime === 1 || is_lifetime === '1') ? 1 : 0;
  const defaultValidUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

  let finalValidUntil = defaultValidUntil;
  if (isLifetimeNum === 1) {
    finalValidUntil = 'LIFETIME';
  } else if (valid_until) {
    finalValidUntil = new Date(valid_until).toISOString();
  }

  const initialStatus = status || 'active';

  try {
    const db = await openDb();
    await db.run(
      `INSERT INTO licenses (uuid, company_name, created_at, valid_until, is_lifetime, status, api_key, created_by) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [uuid, company_name || 'Cliente', created_at, finalValidUntil, isLifetimeNum, initialStatus, apiKey, created_by]
    );

    const newRecord = await db.get('SELECT * FROM licenses WHERE uuid = ?', [uuid]);
    return res.status(201).json({ success: true, license: newRecord });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Editar licença existente (Admin, Operador)
router.put('/api/admin/licenses/:uuid', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  const { uuid } = req.params;
  const { company_name, valid_until, is_lifetime, status, api_key, regenerate_api_key } = req.body;

  try {
    const db = await openDb();
    const record = await db.get('SELECT * FROM licenses WHERE uuid = ?', [uuid]);

    if (!record) {
      return res.status(404).json({ success: false, error: 'Licença não encontrada.' });
    }

    const isLifetimeNum = (is_lifetime === true || is_lifetime === 1 || is_lifetime === '1') ? 1 : 0;

    let updatedValidUntil = record.valid_until;
    if (isLifetimeNum === 1) {
      updatedValidUntil = 'LIFETIME';
    } else if (valid_until) {
      updatedValidUntil = new Date(valid_until).toISOString();
    }

    const updatedStatus = status || record.status || 'active';
    const updatedName = company_name !== undefined ? company_name : record.company_name;

    let updatedApiKey = record.api_key;
    if (regenerate_api_key) {
      updatedApiKey = crypto.randomBytes(24).toString('hex');
    } else if (api_key !== undefined && api_key.trim() !== '') {
      updatedApiKey = api_key.trim();
    } else if (!updatedApiKey) {
      updatedApiKey = crypto.randomBytes(24).toString('hex');
    }

    await db.run(
      `UPDATE licenses 
       SET company_name = ?, valid_until = ?, is_lifetime = ?, status = ?, api_key = ? 
       WHERE uuid = ?`,
      [updatedName, updatedValidUntil, isLifetimeNum, updatedStatus, updatedApiKey, uuid]
    );

    const updatedRecord = await db.get('SELECT * FROM licenses WHERE uuid = ?', [uuid]);
    return res.json({ success: true, license: updatedRecord });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Resetar/Desvincular HWID da licença (Admin, Operador)
router.post('/api/admin/licenses/:uuid/reset-hwid', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  const { uuid } = req.params;
  try {
    const db = await openDb();
    await db.run('UPDATE licenses SET hwid = NULL, hwid_bound_at = NULL WHERE uuid = ?', [uuid]);
    return res.json({ success: true, message: 'HWID desvinculado com sucesso. A licença poderá ser vinculada a uma nova máquina.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Excluir licença (Apenas Admin)
router.delete('/api/admin/licenses/:uuid', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  const { uuid } = req.params;
  try {
    const db = await openDb();
    await db.run('DELETE FROM licenses WHERE uuid = ?', [uuid]);
    return res.json({ success: true, message: 'Licença excluída com sucesso.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * ===================================================================
 *  SEGURANÇA, AUDITORIA E BLACKLIST (Admin, Operador)
 * ===================================================================
 */

// Listar logs de acessos negados / tentativas suspeitas (Admin, Operador)
router.get('/api/admin/access-logs', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  try {
    const db = await openDb();
    const logs = await db.all('SELECT * FROM access_logs ORDER BY created_at DESC LIMIT 100');
    return res.json({ success: true, logs });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Limpar histórico de logs de acesso (Apenas Admin)
router.delete('/api/admin/access-logs', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  try {
    const db = await openDb();
    await db.run('DELETE FROM access_logs');
    return res.json({ success: true, message: 'Logs de acesso limpos com sucesso.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Listar IPs bloqueados (Admin, Operador)
router.get('/api/admin/blocked-ips', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  try {
    const list = await getBlockedIps();
    return res.json({ success: true, blockedIps: list });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Bloquear um IP (Admin, Operador)
router.post('/api/admin/block-ip', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'Endereço IP não informado.' });
  }
  try {
    const blockedBy = req.admin.name || req.admin.username || 'admin';
    await blockIp(ip, reason || 'Bloqueio efetuado via Painel', blockedBy);
    return res.json({ success: true, message: `IP ${ip} bloqueado com sucesso.` });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Desbloquear um IP (Admin, Operador)
router.post('/api/admin/unblock-ip', authenticateAdminToken, requireRole(['admin', 'operator']), async (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'Endereço IP não informado.' });
  }
  try {
    const unblockedBy = req.admin.name || req.admin.username || 'admin';
    await unblockIp(ip, unblockedBy);
    return res.json({ success: true, message: `IP ${ip} desbloqueado com sucesso.` });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Obter Configurações Globais do Serviço (Exclusivo Administrador)
router.get('/api/admin/settings', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  try {
    const settings = await getSystemSettings();
    return res.json({ success: true, settings });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Atualizar Configurações Globais do Serviço (Exclusivo Administrador)
router.put('/api/admin/settings', authenticateAdminToken, requireRole(['admin']), async (req, res) => {
  const { require_mfa_all } = req.body;
  try {
    const updatedSettings = await updateSystemSettings({ require_mfa_all: !!require_mfa_all });
    return res.json({ success: true, settings: updatedSettings, message: 'Configurações globais salvas com sucesso.' });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
