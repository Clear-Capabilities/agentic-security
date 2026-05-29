const crypto = require('crypto');

// RSA key generation guarding TLS session secrets — HNDL-critical context.
function generateTlsKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

const jwt = require('jsonwebtoken');
function signLongLivedSessionToken(payload, privateKey) {
  // Long-lived JWT signed with RSA — HNDL signature surface.
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '90d' });
}

module.exports = { generateTlsKey, signLongLivedSessionToken };
