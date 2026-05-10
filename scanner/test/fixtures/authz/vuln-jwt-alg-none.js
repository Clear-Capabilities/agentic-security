import jwt from 'jsonwebtoken';

export function decodeToken(token) {
  return jwt.verify(token, 'whatever', { algorithm: 'none' });
}
