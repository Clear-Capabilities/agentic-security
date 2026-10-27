// Diagnostic: prints the lowered IR (CFG nodes) of every function in one Haskell file.
// usage: node bench/dag/dev-haskell/irdump.mjs <file.hs>
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildHaskellIR } from '../../../scanner/src/language/haskell-ir.js';

const file = path.resolve(process.argv[2]);
const ir = buildHaskellIR({ [path.basename(file)]: fs.readFileSync(file, 'utf8') });
for (const f of Object.values(ir.perFile)) {
  for (const fn of f.functions) {
    if (fn.name.endsWith('<module>')) continue;
    console.log(`== ${fn.name} params=${JSON.stringify(fn.params)} reached=${fn.hs && fn.hs.reached} ann=${JSON.stringify(fn.paramAnnotations || null)}`);
    for (const [id, n] of Object.entries(fn.cfg.nodes)) {
      const { succ, pred, ...rest } = n;
      if (rest.kind === 'entry' || rest.kind === 'exit' || rest.kind === 'noop') continue;
      console.log(`  ${id} ${JSON.stringify(rest)}`);
    }
  }
}
