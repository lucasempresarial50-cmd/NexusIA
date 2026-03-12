const crypto = require('crypto');

const SECRET      = process.env.JWT_SECRET  || 'nexus-secret-change-this';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@nexus.ai';
const ADMIN_PASS  = process.env.ADMIN_PASS  || 'admin123';

function getUsers() {
  try { return JSON.parse(process.env.USERS_JSON || '[]'); } catch { return []; }
}
function hashStr(str) {
  return crypto.createHash('sha256').update(str + SECRET).digest('hex');
}
function b64(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function makeToken(payload) {
  const data = b64(JSON.stringify(payload));
  const sig  = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
  return data + '.' + sig;
}
function verifyToken(token) {
  try {
    if (!token) return null;
    const dot  = token.lastIndexOf('.');
    const data = token.slice(0, dot);
    const sig  = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
    if (sig !== expected) return null;
    const json = Buffer.from(data.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString();
    const payload = JSON.parse(json);
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

module.exports = function(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body   = req.body || {};
  const action = body.action;
  const email  = (body.email  || '').trim().toLowerCase();
  const password = body.password || '';

  if (action === 'login') {
    if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });

    const adminEmail = (ADMIN_EMAIL || '').trim().toLowerCase();
    if (email === adminEmail && password === ADMIN_PASS) {
      const token = makeToken({ id: 'admin', email, name: 'Admin', role: 'admin', exp: Date.now() + 7*24*60*60*1000 });
      return res.status(200).json({ token, user: { id: 'admin', email, name: 'Admin', role: 'admin', plan: 'admin' } });
    }

    const users = getUsers();
    const user  = users.find(u => (u.email||'').toLowerCase() === email && u.password === hashStr(password) && u.active);
    if (!user) return res.status(401).json({ error: 'Email ou senha incorretos' });

    const token = makeToken({ id: user.id, email: user.email, name: user.name, role: 'user', plan: user.plan, exp: Date.now() + 7*24*60*60*1000 });
    return res.status(200).json({ token, user: { id: user.id, email: user.email, name: user.name, role: 'user', plan: user.plan } });
  }

  if (action === 'verify') {
    const auth  = (req.headers.authorization || '').replace('Bearer ', '');
    const payload = verifyToken(auth);
    if (!payload) return res.status(401).json({ error: 'Token inválido ou expirado' });
    return res.status(200).json({ valid: true, user: payload });
  }

  return res.status(400).json({ error: 'Ação inválida' });
};
