import jwt from 'jsonwebtoken';

export function requireUser(req, res, next) {
  const header = req.headers.authorization ?? '';
  const token = header.replace('Bearer ', '');
  const claims = jwt.decode(token); // @hit
  if (!claims) return res.status(401).end();
  req.user = { id: claims.sub };
  next();
}
