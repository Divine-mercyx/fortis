import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
if (!secret) throw new Error('JWT_SECRET must be set');

export function requireUser(req, res, next) {
  const token = (req.headers.authorization ?? '').replace('Bearer ', '');
  try {
    const claims = jwt.verify(token, secret, { algorithms: ['HS256'] });
    const header = jwt.decode(token, { complete: true });
    req.user = { id: claims.sub, kid: header?.header.kid };
    next();
  } catch {
    res.status(401).end();
  }
}
