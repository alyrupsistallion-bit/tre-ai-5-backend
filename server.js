const express = require('express');
const cors = require('cors');
const jwt = require('jwt-simple');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'tre-ai-secret-key-2024';

app.use(cors());
app.use(express.json());

// Demo users database
const users = [
  { id: '1', email: 'admin@treai.local', password: 'admin123', name: 'Admin', role: 'admin' },
  { id: '2', email: 'user@treai.local', password: 'user123', name: 'User', role: 'user' }
];

// Active tokens store (in production, use Redis or database)
const validTokens = new Map();

// POST /auth/login - Authenticate user
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  const user = users.find(u => u.email === email && u.password === password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  try {
    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
    };
    
    const token = jwt.encode(payload, SECRET);
    validTokens.set(token, payload);
    
    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Token generation failed' });
  }
});

// GET /api/validate - Validate access token
app.get('/api/validate', (req, res) => {
  const token = req.query.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ ok: false, error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.decode(token, SECRET, true);
    const now = Math.floor(Date.now() / 1000);
    
    if (decoded.exp < now) {
      return res.json({ ok: false, error: 'Token expired' });
    }
    
    return res.json({
      ok: true,
      user: {
        id: decoded.id,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role
      }
    });
  } catch (error) {
    return res.json({ ok: false, error: 'Invalid token' });
  }
});

// GET /api/health - Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'TRE-AI Backend is running' });
});

// Start server
app.listen(PORT, () => {
  console.log(`TRE-AI 5.0 Backend running on http://localhost:${PORT}`);
  console.log('Demo credentials:');
  console.log('  Email: admin@treai.local');
  console.log('  Password: admin123');
});
