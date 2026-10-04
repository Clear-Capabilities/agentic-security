const chunk = Buffer.alloc(1024 * 1024, 120);
let n = 0;
const pump = () => { while (n < 40) { n++; if (!process.stdout.write(chunk)) { process.stdout.once('drain', pump); return; } } process.exit(0); };
pump();
