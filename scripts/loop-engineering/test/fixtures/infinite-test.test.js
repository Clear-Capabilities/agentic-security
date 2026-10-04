import test from 'node:test';
const keepAlive = setInterval(() => {}, 1000);
test('never ends', async () => { await new Promise(() => keepAlive); });
