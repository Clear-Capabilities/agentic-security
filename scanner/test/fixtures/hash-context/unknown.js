// MD5 with no surrounding context. Severity should be downgraded to medium.
const crypto = require('crypto');

function someHash(buf) {
  const h = crypto.createHash('sha1').update(buf).digest('hex');
  return h;
}

module.exports = { someHash };
