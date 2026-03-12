const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'nexus-secret-change-this';

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
function hashPwd(str) {
  return crypto.createHash('sha256').update(str + SECRET).digest('hex');
}
function getUsers() {
  try { return JSON.parse(process.env.USERS_JSON || '[]'); } catch { return []; }
}

module.exports = function(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const auth    = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(auth);
  if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });

  const { action, user } = req.body || {};
  const users = getUsers();

  if (action === 'list') {
    return res.status(200).json({ users: users.map(u => ({ ...u, password: '***' })) });
  }

  if (action === 'generate') {
    if (!user || !user.email || !user.password || !user.name) {
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
    return res.status(200).json({
      user: { ...newUser, password: '***' },
      users_json: JSON.stringify(updated),
    });
  }

  return res.status(400).json({ error: 'Ação inválida' });
};
