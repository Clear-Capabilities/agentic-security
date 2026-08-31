function handleCheckout(req, res) {
  const cardNumber = req.body.card_number;
  res.send('ok');
}

function unrelatedLogging(logger, status) {
  logger.info('checkout finished', { status });
}
