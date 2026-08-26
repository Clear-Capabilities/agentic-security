const crypto = require('crypto');

function logHashed(req) {
  const ssn = req.body.value;
  const hashed = crypto.createHash(ssn);
  console.log(hashed);
}

function logRaw(req) {
  const email = req.body.value;
  console.log(email);
}

module.exports = { logHashed, logRaw };
