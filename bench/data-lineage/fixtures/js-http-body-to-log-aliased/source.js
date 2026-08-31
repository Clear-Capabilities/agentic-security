function handleCheckout(req, logger) {
  const body = req.body;
  const cardNumber = body.card_number;
  logger.info('checkout', cardNumber);
}
