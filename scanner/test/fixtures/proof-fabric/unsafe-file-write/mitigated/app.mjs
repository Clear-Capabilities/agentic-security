// Mitigated: refuses any absolute path and confines writes to the current directory.
import fs from 'node:fs';
import path from 'node:path';
const target = process.argv[2] || '';
if (!path.isAbsolute(target) && !target.includes('..')) {
  try { fs.writeFileSync(path.join(process.cwd(), target), 'written-by-fixture'); } catch { /* ignore */ }
}
