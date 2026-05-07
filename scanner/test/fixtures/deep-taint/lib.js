// Helper file: receives the (tainted) value and runs an unsafe SQL query.
function lookupUser(username) {
  return db.query("SELECT * FROM users WHERE name = '" + username + "'");
}

module.exports = { lookupUser };
