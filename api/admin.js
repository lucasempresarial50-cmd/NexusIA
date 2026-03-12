// Nexus AI — api/admin.js (full version with update/delete/stats)
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

  const { action, user, userId, updates, newPassword } = req.body || {};
  const users = getUsers();

  // ── LIST ──────────────────────────────────────────────────────────────────
  if (action === 'list') {
    return res.status(200).json({
      users: users.map(u => ({ ...u, password: undefined }))
    });
  }

  // ── GENERATE ──────────────────────────────────────────────────────────────
  if (action === 'generate') {
    if (!user || !user.email || !user.password || !user.name) {
      return res.status(400).json({ error: 'email, password e name obrigatórios' });
    }
    if (users.find(u => u.email === user.email)) {
      return res.status(400).json({ error: 'E-mail já cadastrado' });
    }
    const newUser = {
      id:         Date.now().toString(),
      email:      user.email.toLowerCase().trim(),
      password:   hashPwd(user.password),
      name:       user.name.trim(),
      plan:       user.plan  || 'starter',
      niche:      user.niche || 'sales',
      active:     true,
      usage:      0,
      conv_limit: user.conv_limit || (user.plan === 'agency' ? 9999 : user.plan === 'pro' ? 1000 : 200),
      created:    new Date().toISOString(),
    };
    const updated = [...users, newUser];
    return res.status(200).json({
      user:       { ...newUser, password: undefined },
      users_json: JSON.stringify(updated),
    });
  }

  // ── UPDATE ────────────────────────────────────────────────────────────────
  if (action === 'update') {
    if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado' });
    const merged = { ...users[idx] };
    const allowed = ['name','email','plan','niche','active','usage','conv_limit'];
    if (updates) allowed.forEach(k => { if (updates[k] !== undefined) merged[k] = updates[k]; });
    if (newPassword && newPassword.trim()) merged.password = hashPwd(newPassword.trim());
    users[idx] = merged;
    return res.status(200).json({
      user:       { ...merged, password: undefined },
      users_json: JSON.stringify(users),
    });
  }

  // ── DELETE ────────────────────────────────────────────────────────────────
  if (action === 'delete') {
    if (!userId) return res.status(400).json({ error: 'userId obrigatório' });
    const updated = users.filter(u => u.id !== userId);
    if (updated.length === users.length) return res.status(404).json({ error: 'Usuário não encontrado' });
    return res.status(200).json({ users_json: JSON.stringify(updated) });
  }

  // ── STATS ─────────────────────────────────────────────────────────────────
  if (action === 'stats') {
    const prices = { starter: 97, pro: 197, agency: 497 };
    const mrr = users.filter(u => u.active).reduce((s, u) => s + (prices[u.plan] || 97), 0);
    const byPlan = users.reduce((acc, u) => { acc[u.plan] = (acc[u.plan] || 0) + 1; return acc; }, {});
    return res.status(200).json({ total: users.length, active: users.filter(u=>u.active).length, mrr, byPlan });
  }

  return res.status(400).json({ error: 'Ação inválida: ' + action });
};
