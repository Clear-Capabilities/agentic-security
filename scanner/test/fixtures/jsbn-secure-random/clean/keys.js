// Synthetic fixture: the same keys drawn from the platform CSPRNG.
const crypto = require('crypto');
const { BigInteger } = require('jsbn');

const rng = { nextBytes(bytes) { const b = crypto.randomBytes(bytes.length); for (let i = 0; i < bytes.length; i++) bytes[i] = b[i]; } };

function newPrivateKey(order) {
  return new BigInteger(order.bitLength(), rng).mod(order);
}

module.exports = { newPrivateKey };
