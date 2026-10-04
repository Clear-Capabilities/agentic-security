// Asks an interactive question and waits for an answer on stdin.
process.stdout.write('Proceed? [y/N] ');
let got = '';
process.stdin.on('data', (d) => { got += d; });
process.stdin.on('end', () => process.exit(got.trim() ? 0 : 3));
