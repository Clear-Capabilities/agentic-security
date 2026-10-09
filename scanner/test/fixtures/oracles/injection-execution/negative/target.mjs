// Fixed: the input is a separate argv element, so no shell parses it.
import { execFileSync } from 'node:child_process';
export function handler(input) {
  return execFileSync('echo', [input], { encoding: 'utf8' });
}
