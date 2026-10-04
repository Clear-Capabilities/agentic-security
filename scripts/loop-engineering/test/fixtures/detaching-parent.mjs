// Spawns a nested child and a deliberately setsid()-detached grandchild, then
// idles. argv[2] = path to write the pids to.
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const nested = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore' });
const detached = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'ignore', detached: true });
detached.unref();
writeFileSync(process.argv[2], JSON.stringify({ nested: nested.pid, detached: detached.pid }));
setInterval(() => {}, 1000);
