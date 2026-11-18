// Synthetic fixture: the webhook secret falls back to the empty string.
const crypto = require('crypto');

function verifyWebhook(body, signature, config) {
  const secret = config.webhookSecret || '';
  const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

module.exports = { verifyWebhook };
