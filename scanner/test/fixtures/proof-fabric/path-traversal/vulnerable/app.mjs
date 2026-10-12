// Deliberately vulnerable: joins user input onto a base directory with no traversal check.
import fs from 'node:fs';
import path from 'node:path';
const base = path.join(process.cwd(), 'public');
fs.mkdirSync(base, { recursive: true });
const requested = process.argv[2] || '';
const target = path.join(base, requested);
try { fs.writeFileSync(target, 'written-by-fixture'); } catch { /* ignore */ }
