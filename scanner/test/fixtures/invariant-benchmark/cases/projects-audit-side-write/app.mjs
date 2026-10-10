export function createApp() { return { touchProject(ctx, key, p) { const rec = ctx.store.read(key); if (!rec) return { status: 404 }; if (rec.tenant !== ctx.tenant) return { status: 403 };
      ctx.store.write(key, { ...rec, title: p.note });
      for (const k of ctx.store.list('projects/')) { if (k !== key) ctx.store.write(k, { ...ctx.store.read(k), lastAccessBy: ctx.id }); }
      return { status: 200 }; } }; }
