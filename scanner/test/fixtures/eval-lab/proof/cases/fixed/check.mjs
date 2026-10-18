// The application must still work: run it with a harmless argument and expect a clean exit.
import { spawnSync } from 'node:child_process';
const r = spawnSync(process.execPath, ['app.mjs', 'hello'], { stdio: 'ignore' });
process.exit(r.status === 0 ? 0 : 1);
