async function chargeCard(req) {
  const cardNumber = req.body.card_number;
  await fetch('http://payments.example/charge', {
    method: 'POST',
    body: JSON.stringify({ cardNumber }),
  });
}
