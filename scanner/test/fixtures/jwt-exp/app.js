const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// VULNERABLE: no expiresIn, no exp claim
function issueBad(user) {
  return jwt.sign({ id: user.id, role: user.role }, process.env.SECRET);
}

// VULNERABLE: weak bcrypt cost factor
async function hashBad(password) {
  return await bcrypt.hash(password, 4);
}

// SAFE: expiresIn set, no finding
function issueGood(user) {
  return jwt.sign({ id: user.id }, process.env.SECRET, { algorithm: 'HS256', expiresIn: '15m' });
}

// SAFE: bcrypt cost 12, no finding
async function hashGood(password) {
  return await bcrypt.hash(password, 12);
}

// SAFE: exp claim in payload
function issueWithExpClaim(user) {
  return jwt.sign({ id: user.id, exp: Math.floor(Date.now() / 1000) + 900 }, process.env.SECRET);
}

module.exports = { issueBad, hashBad, issueGood, hashGood, issueWithExpClaim };
