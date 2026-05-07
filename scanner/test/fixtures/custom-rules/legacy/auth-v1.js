// This file uses MD5 for password hashing — should normally fire a critical
// finding, but the custom suppression in rules.yml exempts it (active migration).
const crypto = require('crypto');

function legacyHash(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { legacyHash };
