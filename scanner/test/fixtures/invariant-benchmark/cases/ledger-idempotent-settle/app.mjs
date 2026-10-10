export function createApp() { return { settle(ctx, key, p) {
      if (ctx.store.read('seen/' + p.requestId)) return { status: 200 };
      ctx.store.write('seen/' + p.requestId, { done: true });
      const payer = ctx.store.read('ledger/payer'); ctx.store.write('ledger/payer', { ...payer, amount: payer.amount - p.amount });
      const payee = ctx.store.read('ledger/payee'); ctx.store.write('ledger/payee', { ...payee, amount: payee.amount + p.amount });
      return { status: 200 }; } }; }
