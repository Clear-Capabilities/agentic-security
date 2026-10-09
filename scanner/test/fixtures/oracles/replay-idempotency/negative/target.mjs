// Fixed: a request whose idempotency key was already seen is acknowledged without charging again.
export function createHandler(deps) {
  const seen = new Set();
  return async function handle(request) {
    if (seen.has(request.idempotencyKey)) return { status: 'duplicate' };
    seen.add(request.idempotencyKey);
    await deps.chargeCard(request.idempotencyKey, request.amountCents);
    return { status: 'charged' };
  };
}
