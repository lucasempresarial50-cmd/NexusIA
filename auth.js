// api/auth.js
const crypto = require('crypto');

const SECRET      = process.env.JWT_SECRET  || 'nexus-secret-change-this';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@nexus.ai';
const ADMIN_PASS  = process.env.ADMIN_PASS  || 'admin123';

function getUsers() {
  try { return JSON.parse(process.env.USERS_JSON || '[]'); } catch { return []; }
}
function hash(str) {
  return crypto.createHash('sha256').update(str + SECRET).digest('hex');
}
function makeToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}
function verifyToken(token) {
  try {
    const [data, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, email, password } = req.body || {};

  if (action === 'login') {
    if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
    if (email === ADMIN_EMAIL && password === ADMIN_PASS) {
      const token = makeToken({ id: 'admin', email, name: 'Admin', role: 'admin', exp: Date.now() + 7*24*60*60*1000 });
      return res.json({ token, user: { id: 'admin', email, name: 'Admin', role: 'admin', plan: 'admin' } });
    }
    const users = getUsers();
    const user  = users.find(u => u.email === email && u.password === hash(password) && u.active);
    if (!user) return res.status(401).json({ error: 'Email ou senha incorretos' });
    const token = makeToken({ id: user.id, email: user.email, name: user.name, role: 'user', plan: user.plan, exp: Date.now() + 7*24*60*60*1000 });
    return res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: 'user', plan: user.plan } });
  }

  if (action === 'verify') {
    const auth  = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');
    const payload = verifyToken(token);
    if (!payload) return res.status(401).json({ error: 'Token inválido ou expirado' });
    return res.json({ valid: true, user: payload });
  }

  return res.status(400).json({ error: 'Ação inválida' });
};
