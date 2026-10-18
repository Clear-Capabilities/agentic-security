// Mitigated: no shell, argv passed as discrete arguments, never concatenated into a command string.
import { spawnSync } from 'node:child_process';
const userInput = process.argv[2] || '';
spawnSync('echo', ['hello', userInput], { stdio: 'ignore', shell: false });
