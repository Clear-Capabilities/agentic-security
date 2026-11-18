// Synthetic fixture: private keys drawn from the big-integer package's own generator.
const { BigInteger, SecureRandom } = require('jsbn');

const rng = new SecureRandom();

function newPrivateKey(order) {
  return new BigInteger(order.bitLength(), rng).mod(order);
}

module.exports = { newPrivateKey };
