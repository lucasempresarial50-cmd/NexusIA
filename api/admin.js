// api/admin.js
const crypto = require('crypto');

const SECRET      = process.env.JWT_SECRET  || 'nexus-secret-change-this';

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

function hashPwd(str) {
  return crypto.createHash('sha256').update(str + SECRET).digest('hex');
}

function getUsers() {
  try { return JSON.parse(process.env.USERS_JSON || '[]'); } catch { return []; }
}

module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const auth    = req.headers.authorization || '';
  const payload = verifyToken(auth.replace('Bearer ', ''));
  if (!payload || payload.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const { action, user } = req.body || {};
  const users = getUsers();

  if (action === 'list') {
    return res.json({ users: users.map(u => ({ ...u, password: '***' })) });
  }

  if (action === 'generate') {
    if (!user?.email || !user?.password || !user?.name) {
      return res.status(400).json({ error: 'email, password e name obrigatórios' });
    }
    const newUser = {
      id:       Date.now().toString(),
      email:    user.email,
      password: hashPwd(user.password),
      name:     user.name,
      plan:     user.plan || 'starter',
      active:   true,
      created:  new Date().toISOString(),
    };
    const updated = [...users, newUser];
    return res.json({
      user: { ...newUser, password: '***' },
      users_json: JSON.stringify(updated),
      instruction: 'Cole users_json em USERS_JSON nas env vars do Vercel e faça Redeploy.',
    });
  }

  return res.status(400).json({ error: 'Ação inválida' });
};
