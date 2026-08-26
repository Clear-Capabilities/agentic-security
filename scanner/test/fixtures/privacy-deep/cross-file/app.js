const { getSSN, getCount } = require('./helper.js');

function logViaHelper(req) {
  const count = req.body.value;
  console.log(getSSN(count));
}

function logCleanViaHelper(req) {
  const other = req.body.value;
  console.log(getCount(other));
}

module.exports = { logViaHelper, logCleanViaHelper };
