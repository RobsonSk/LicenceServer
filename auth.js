import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'license-server-super-secret-jwt-key-2026';

export function generateAdminToken(username = 'admin', name = 'Administrador', role = 'admin') {
  return jwt.sign({ username, name, role }, JWT_SECRET, { expiresIn: '24h' });
}

export function authenticateAdminToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') 
    ? authHeader.split(' ')[1] 
    : (req.headers['x-access-token'] || req.query.token);

  const isApi = req.path.startsWith('/api/');

  if (!token) {
    if (req.accepts('html') && !req.xhr && req.method === 'GET' && !isApi) {
      return res.redirect('/admin/login');
    }
    return res.status(401).json({ error: 'Acesso negado. Token de autenticação ausente.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    if (req.accepts('html') && !req.xhr && req.method === 'GET' && !isApi) {
      return res.redirect('/admin/login');
    }
    return res.status(403).json({ error: 'Token inválido ou expirado.' });
  }
}

export function requireRole(allowedRoles = []) {
  return (req, res, next) => {
    if (!req.admin || !allowedRoles.includes(req.admin.role)) {
      return res.status(403).json({ success: false, error: 'Acesso negado. Permissão insuficiente para esta funcionalidade.' });
    }
    next();
  };
}
