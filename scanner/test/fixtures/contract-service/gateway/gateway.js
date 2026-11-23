// Gateway: verifies the session token and forwards the request to the API with the tenant as a header.
import jwt from 'jsonwebtoken';
import { forward } from './proxy.js';

export function handle(req, res) {
  const claims = jwt.verify(req.headers.authorization, process.env.SIGNING_KEY);
  req.headers['x-tenant'] = claims.tenant;
  return forward(req, res, 'http://api.internal');
}
