// Cache-key use of MD5 — non-security; should be suppressed (or info).
const crypto = require('crypto');

function buildCacheKey(args) {
  const cacheKey = crypto.createHash('md5').update(JSON.stringify(args)).digest('hex');
  return cacheKey;
}

module.exports = { buildCacheKey };
