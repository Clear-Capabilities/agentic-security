function handleList(req, logger) {
  const page = req.query.page;
  logger.info('listing page', page);
}
