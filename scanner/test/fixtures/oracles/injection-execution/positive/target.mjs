// Vulnerable: the input is concatenated into a shell command line.
import { execSync } from 'node:child_process';
export function handler(input) {
  return execSync('echo ' + input, { encoding: 'utf8' });
}
