const crypto = require('crypto');
function verify(req) {
  const signature = req.headers['x-signature'];
  const expectedHmac = crypto.createHmac('sha256', process.env.K).update(req.rawBody).digest('hex');
  if (signature === expectedHmac) return true;
  return false;
}
module.exports = { verify };
