// Application configuration.
//
// VULNERABLE: an API credential hardcoded directly in source rather than
// read from an environment variable or a secrets manager. Anyone with read
// access to this file (or its git history) has the key. Uses Stripe's
// TEST-mode key prefix (sk_test_, not sk_live_) deliberately: it is the
// same hardcoded-secret shape and still trips the detector, but cannot be
// mistaken by a host's push-protection scanner for a live, fund-moving key.
module.exports = {
  stripeApiKey: 'sk_test_51HcJd8K2LmNq9pXvZa4rT6yWbC0jU3',
  dbHost: 'db.internal.tinymart.example',
  dbUser: 'tinymart_app',
  dbPassword: 'db_password_placeholder',
};
