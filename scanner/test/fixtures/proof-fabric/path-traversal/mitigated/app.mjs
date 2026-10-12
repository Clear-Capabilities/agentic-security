// Mitigated: resolves and confines the path to the base directory before any write.
import fs from 'node:fs';
import path from 'node:path';
const base = path.join(process.cwd(), 'public');
fs.mkdirSync(base, { recursive: true });
const requested = process.argv[2] || '';
const resolved = path.resolve(base, requested);
if (resolved === base || resolved.startsWith(base + path.sep)) {
  fs.writeFileSync(resolved, 'written-by-fixture');
}
