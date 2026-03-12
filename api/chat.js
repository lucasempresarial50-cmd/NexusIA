// api/chat.js — Proxy seguro para o Groq
// Sua API Key fica AQUI no servidor, nunca chega ao cliente

export default async function handler(req, res) {
  // Permite requisições do seu frontend
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Chave fica no servidor — cliente nunca vê
  const GROQ_KEY = process.env.GROQ_API_KEY;

  if (!GROQ_KEY) {
    return res.status(500).json({ error: 'API Key não configurada no servidor' });
  }

  try {
    const { messages, system, temperature = 0.7 } = req.body;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_KEY}`,
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: system || 'Você é um assistente de vendas.' },
          ...messages,
        ],
        max_tokens: 1024,
        temperature,
      }),
    });

    if (!response.ok) {
      const err = await response.json();
      return res.status(response.status).json({ error: err.error?.message || 'Erro Groq' });
    }

    const data = await response.json();
    return res.status(200).json({
      content: data.choices[0].message.content,
    });

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
