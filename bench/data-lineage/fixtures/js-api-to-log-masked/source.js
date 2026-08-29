function maskCard(pan) {
  return pan.slice(0, 4) + '********' + pan.slice(-4);
}

function handleCheckout(req, logger) {
  const cardNumber = req.body.card_number;
  const maskedPan = maskCard(cardNumber);
  logger.info('processing payment', { pan: maskedPan });
}
