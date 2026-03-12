// api/admin.js — Painel admin: gerenciar clientes
import crypto from 'crypto';

const SECRET      = process.env.JWT_SECRET  || 'nexus-secret-change-this';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@nexus.ai';

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

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Só admin
  const auth    = req.headers.authorization || '';
  const payload = verifyToken(auth.replace('Bearer ', ''));
  if (!payload || payload.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const { action, user } = req.body || {};
  const users = getUsers();

  // ── Listar usuários ──
  if (action === 'list') {
    return res.json({ users: users.map(u => ({ ...u, password: '***' })) });
  }

  // ── Gerar hash de senha (para exibir ao admin) ──
  if (action === 'hash') {
    return res.json({ hash: hashPwd(user.password), hint: 'Adicione manualmente no USERS_JSON' });
  }

  // ── Gerar JSON para novo usuário ──
  if (action === 'generate') {
    if (!user?.email || !user?.password || !user?.name) {
      return res.status(400).json({ error: 'email, password e name são obrigatórios' });
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
    const updatedUsers = [...users, newUser];
    return res.json({
      user: { ...newUser, password: '***' },
      users_json: JSON.stringify(updatedUsers),
      instruction: 'Copie o valor de users_json e cole em USERS_JSON nas variáveis de ambiente do Vercel, depois faça Redeploy.',
    });
  }

  return res.status(400).json({ error: 'Ação inválida' });
}
