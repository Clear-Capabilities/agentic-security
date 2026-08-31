function extractCard(req) {
  return req.body.card_number;
}

function handleCheckout(req, logger) {
  const cardNumber = extractCard(req);
  logger.info('checkout', cardNumber);
}
