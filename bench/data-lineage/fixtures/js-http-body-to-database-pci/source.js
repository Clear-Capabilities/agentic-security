function handleCheckout(req, db) {
  const cardNumber = req.body.card_number;
  const sql = `SELECT * FROM cards WHERE number = '${cardNumber}'`;
  db.query(sql);
}
