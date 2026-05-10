import jwt from 'jsonwebtoken';

const JWT_SECRET = "supersecret123";

export function sign(user) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { algorithm: 'HS256' });
}

export function verify(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}
