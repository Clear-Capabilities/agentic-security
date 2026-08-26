function getSSN(rawInput) {
  const ssn = rawInput;
  return ssn;
}

function logViaHelper(req) {
  const count = req.body.value;
  console.log(getSSN(count));
}

module.exports = { getSSN, logViaHelper };
