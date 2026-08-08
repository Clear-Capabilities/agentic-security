const crypto = require('crypto');
function verify(req) {
  const signature = Buffer.from(req.headers['x-signature'], 'hex');
  const expectedHmac = crypto.createHmac('sha256', process.env.K).update(req.rawBody).digest();
  if (signature.length !== expectedHmac.length) return false;
  return crypto.timingSafeEqual(signature, expectedHmac);
}
module.exports = { verify };
