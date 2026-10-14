const { db } = require('./db');

async function findOwned(user, id) {
  return db.query('SELECT * FROM projects WHERE id = $1', [id]);
}

module.exports = { findOwned };
