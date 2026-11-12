import jwt from 'jsonwebtoken';

const SECRET = process.env.JWT_SECRET || 'nolt-dev-secret'; // @hit

export function issueAccess(userId: string) {
  return jwt.sign({ sub: userId }, 'hard-coded-signing-key', { expiresIn: '15m' }); // @hit
}

export function issueForever(userId: string) {
  return jwt.sign({ sub: userId }, SECRET); // @hit
}

export function issueRefresh(userId: string) {
  return jwt.sign({ sub: userId, typ: 'refresh' }, SECRET, { expiresIn: '7d' });
}

export function checkOld(token: string) {
  return jwt.verify(token, SECRET, { ignoreExpiration: true }); // @hit
}

export function checkNone(token: string) {
  return jwt.verify(token, SECRET, { algorithms: ['none'] }); // @hit
}

export function check(token: string) {
  return jwt.verify(token, SECRET, { algorithms: ['HS256'] });
}
