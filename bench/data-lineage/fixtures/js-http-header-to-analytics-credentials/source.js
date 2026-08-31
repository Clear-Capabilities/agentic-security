function trackRequest(req, analytics) {
  const apiKey = req.headers.api_key;
  analytics.track({ event: 'request', key: apiKey });
}
