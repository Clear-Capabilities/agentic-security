// PRD "Runtime-Corroborated Security Twin" required fixture — the 5
// properties the PRD names, all in one small, real distributed app:
//
// 1. "one static path executes"             -> User.create(email), observed ALLOWED
// 2. "one static path does not execute"      -> fetch('https://api.stripe.com/...'), never observed
// 3. "one runtime path missing from static"  -> an unmatched runtime observation (see telemetry/)
// 4. "a sensitive flow crossing a boundary"  -> req.body.email -> analytics.track(...) (external, PII)
// 5. "a path blocked by authorization"       -> sqs.sendMessage(OrdersQueue), observed DENIED
const analytics = require('analytics-node')('write-key');
const User = require('./models/user');
const sqs = require('./sqs-client');

async function handleCheckout(req) {
  const email = req.body.email;
  // Sensitive (PII) flow crossing a trust boundary to a third-party
  // analytics provider. Its destination never resolves to a literal host,
  // so no telemetry adapter in this PRD can ever corroborate it — a real,
  // disclosed architectural limit, not an oversight.
  analytics.track({ userId: email, event: 'checkout' });
  // A static path that never executes in this scenario — no telemetry
  // import below ever names api.stripe.com.
  await fetch('https://api.stripe.com/v1/charges', { method: 'POST' });
  // Observed ALLOWED in production (telemetry/k8s-audit-allowed.jsonl).
  await User.create({ email });
  // Observed BLOCKED by authorization (telemetry/k8s-audit-denied.jsonl).
  await sqs.sendMessage({ QueueUrl: 'OrdersQueue', MessageBody: 'checkout' });
}

module.exports = { handleCheckout };
