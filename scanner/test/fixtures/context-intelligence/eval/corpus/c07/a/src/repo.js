const { db } = require('./db');

async function findOwned(user, id) {
  return db.query('SELECT * FROM projects WHERE id = $1 AND owner_id = $2', [id, user.id]);
}

module.exports = { findOwned };
