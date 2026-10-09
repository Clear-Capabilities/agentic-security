// Same webhook with the event id recorded before the effect.
export function createWebhookHandler(deps) {
  const processed = new Set();
  return async function handleWebhook(event) {
    if (!event || typeof event.eventId !== 'string') return { status: 'ignored' };
    if (processed.has(event.eventId)) return { status: 'duplicate' };
    processed.add(event.eventId);
    await deps.creditAccount(event.accountId, event.amountCents);
    return { status: 'credited' };
  };
}
