// ETag generation with SHA1 — non-security; should be suppressed.
const crypto = require('crypto');

function setEtag(res, body) {
  const etag = crypto.createHash('sha1').update(body).digest('hex');
  res.setHeader('ETag', etag);
}

module.exports = { setEtag };
