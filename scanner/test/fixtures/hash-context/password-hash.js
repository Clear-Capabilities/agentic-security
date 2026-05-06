// MD5 used for password hashing — keep critical.
const crypto = require('crypto');

async function verifyPassword(plain, storedHash) {
  const password = plain;
  const hashed = crypto.createHash('md5').update(password).digest('hex');
  if (hashed === storedHash) return true;
  return false;
}

module.exports = { verifyPassword };
