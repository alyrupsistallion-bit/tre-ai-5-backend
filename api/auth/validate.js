import cors from 'cors';

const corsHandler = cors({ origin: '*' });

function verify(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [headerB64, bodyB64, signatureB64] = parts;
    const signature = require('crypto')
      .createHmac('sha256', secret)
      .update(`${headerB64}.${bodyB64}`)
      .digest('base64')
      .replace(/=/g, '');
    
    if (signature !== signatureB64) return null;
    
    const payload = JSON.parse(Buffer.from(bodyB64, 'base64').toString());
    return payload;
  } catch (e) {
    return null;
  }
}

export default function handler(req, res) {
  corsHandler(req, res, () => {
    const token = req.query.token || (req.headers.authorization?.replace('Bearer ', ''));
    
    if (!token) {
      return res.status(200).json({ ok: false, error: 'No token provided' });
    }
    
    const secret = process.env.JWT_SECRET || 'tre-ai-secret-key-2024';
    const decoded = verify(token, secret);
    
    if (!decoded) {
      return res.status(200).json({ ok: false, error: 'Invalid token' });
    }
    
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp < now) {
      return res.status(200).json({ ok: false, error: 'Token expired' });
    }
    
    return res.status(200).json({
      ok: true,
      user: {
        id: decoded.id,
        email: decoded.email,
        name: decoded.name,
        role: decoded.role
      }
    });
  });
}
