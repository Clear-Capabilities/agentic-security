// Deliberately vulnerable fixture: shells out with unsanitized input. For the proof-fabric test corpus only.
import { execSync } from 'node:child_process';
const userInput = process.argv[2] || '';
try { execSync(`echo hello; ${userInput}`, { stdio: 'ignore' }); } catch { /* ignore */ }
