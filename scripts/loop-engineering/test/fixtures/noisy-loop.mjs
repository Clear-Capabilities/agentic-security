// Floods both streams forever, honouring backpressure so the child never
// exhausts its own heap: the supervisor, not the child, must end it.
const line = 'x'.repeat(4000) + '\n';
const pump = () => {
  for (let i = 0; i < 50; i++) {
    const a = process.stdout.write(line);
    const b = process.stderr.write(line);
    if (!a || !b) { setTimeout(pump, 1); return; }
  }
  setImmediate(pump);
};
pump();
