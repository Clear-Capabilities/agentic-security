function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  const alias = cardNumber;
  logger.info('checkout', alias);
}
