export function createApp() { return { refund(ctx, key, p) { ctx.store.write('seen/' + p.requestId, { done: true }); ctx.emit('refund-issued', { key: p.requestId }); return { status: 200 }; } }; }
