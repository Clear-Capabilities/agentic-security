// Payment provider webhook. Providers redeliver events, so the handler must be idempotent.
// Vulnerable: the event id is read but never remembered, so each redelivery credits the account again.
export function createWebhookHandler(deps) {
  return async function handleWebhook(event) {
    if (!event || typeof event.eventId !== 'string') return { status: 'ignored' };
    await deps.creditAccount(event.accountId, event.amountCents);
    return { status: 'credited' };
  };
}
