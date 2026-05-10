import jwt from 'jsonwebtoken';

export function decode(token) {
  return jwt.verify(token, process.env.JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
}
