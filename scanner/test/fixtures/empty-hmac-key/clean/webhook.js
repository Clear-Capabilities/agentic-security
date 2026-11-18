// Synthetic fixture: no secret configured means no verification succeeds.
const crypto = require('crypto');

function verifyWebhook(body, signature, config) {
  const secret = config.webhookSecret;
  if (!secret) throw new Error('webhook secret is not configured');
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

module.exports = { verifyWebhook };
