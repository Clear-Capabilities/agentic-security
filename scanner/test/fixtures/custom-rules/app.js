// Custom source + sink: rules.yml declares getCurrentUser() as a session source
// and db.executeRaw() as a SQL sink. The flow below should fire the custom rule.
const db = require('./db');

function getRoles() {
  const user = getCurrentUser();
  return db.executeRaw('SELECT * FROM roles WHERE user_id = ' + user.id);
}

module.exports = { getRoles };
