// Deliberately vulnerable: writes to an absolute, attacker-supplied path with no containment check.
import fs from 'node:fs';
const target = process.argv[2] || '';
try { fs.writeFileSync(target, 'written-by-fixture'); } catch { /* ignore */ }
