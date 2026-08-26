function logUserRecord(req) {
  const socialSecurityNumber = req.body.ssnValue;
  console.log(socialSecurityNumber);
}

function logRequestCount(req) {
  const count = req.body.count;
  console.log(count);
}

module.exports = { logUserRecord, logRequestCount };
