const crypto = require('crypto');

// AES-256-GCM is symmetric — not impacted by Shor. (Grover does halve the
// effective bit strength but AES-256 retains 128-bit PQ security, which is
// still well above the policy floor.)
function encryptSymmetric(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { ct: Buffer.concat([cipher.update(plaintext), cipher.final()]), iv };
}

module.exports = { encryptSymmetric };
