import cors from 'cors';

const corsHandler = cors({ origin: '*' });

const users = [
  { id: '1', email: 'admin@treai.local', password: 'admin123', name: 'Admin', role: 'admin' },
  { id: '2', email: 'user@treai.local', password: 'user123', name: 'User', role: 'user' }
];

function sign(payload, secret) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64').replace(/=/g, '');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/=/g, '');
  const signature = require('crypto')
    .createHmac('sha256', secret)
    .update(`${header}.${body}`)
    .digest('base64')
    .replace(/=/g, '');
  return `${header}.${body}.${signature}`;
}

export default function handler(req, res) {
  corsHandler(req, res, () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = users.find(u => u.email === email && u.password === password);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const secret = process.env.JWT_SECRET || 'tre-ai-secret-key-2024';
    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60)
    };

    const token = sign(payload, secret);

    return res.status(200).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  });
}
