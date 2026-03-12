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

module.exports = async function(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const auth  = (req.headers.authorization || '').replace('Bearer ', '');
  const user  = verifyToken(auth);
  if (!user) return res.status(401).json({ error: 'Não autorizado. Faça login.' });

  const GROQ_KEY = process.env.GROQ_API_KEY;
  if (!GROQ_KEY) return res.status(500).json({ error: 'API Key não configurada no servidor' });

  const { messages, system, temperature = 0.7 } = req.body || {};

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + GROQ_KEY },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'system', content: system || 'Você é um assistente de vendas.' }, ...messages],
        max_tokens: 1024,
        temperature,
      }),
    });
    if (!response.ok) {
      const err = await response.json();
      return res.status(response.status).json({ error: err.error?.message || 'Erro Groq' });
    }
    const data = await response.json();
    return res.status(200).json({ content: data.choices[0].message.content });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
};
