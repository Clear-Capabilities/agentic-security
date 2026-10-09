// Vulnerable: the idempotency key is accepted but never remembered, so a redelivered request charges again.
export function createHandler(deps) {
  return async function handle(request) {
    await deps.chargeCard(request.idempotencyKey, request.amountCents);
    return { status: 'charged' };
  };
}
