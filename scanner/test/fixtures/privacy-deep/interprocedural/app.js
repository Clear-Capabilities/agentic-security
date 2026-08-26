// getSSN's OWN body classifies its local "ssn" declaration as PII,
// independent of what the caller passed in -- this isolates interprocedural
// resolution from the pre-existing "call args are tainted" check, since the
// call-site argument ("count"/"other") is never itself PII-shaped.
function getSSN(rawInput) {
  const ssn = rawInput;
  return ssn;
}

function getCount(rawInput) {
  const count = rawInput;
  return count;
}

function logViaHelper(req) {
  const count = req.body.value;
  console.log(getSSN(count));
}

function logCleanViaHelper(req) {
  const other = req.body.value;
  console.log(getCount(other));
}

module.exports = { getSSN, getCount, logViaHelper, logCleanViaHelper };
