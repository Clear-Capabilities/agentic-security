// Where an advisory snapshot may come from (trust boundary).
//
// An advisory snapshot decides which dependencies are reported as vulnerable. A scanned project is untrusted input: if the project could
// supply its own snapshot, a pull request could ship an empty, perfectly well-formed, freshly dated one and the scan would report
// "complete" with the vulnerable dependency gone. So a snapshot is accepted only from the operator:
//   1. the environment variable named by the caller (a path the operator set), or
//   2. a file in the operator's per-user configuration directory ($XDG_CONFIG_HOME/agentic-security, or ~/.config/agentic-security),
//      the same directory that holds the per-install signing key.
// A file of the same name inside the scanned project is never read. It is reported, so the operator knows why it had no effect.

import { existsSync, lstatSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { statePath } from '../posture/state-dir.js';

/** The operator's per-user configuration directory. */
export function operatorConfigDir(env = process.env) {
  const base = env.XDG_CONFIG_HOME && env.XDG_CONFIG_HOME.length ? env.XDG_CONFIG_HOME : join(homedir(), '.config');
  return join(base, 'agentic-security');
}

const isRegularFile = (p) => { try { return lstatSync(p).isFile(); } catch { return false; } };

/**
 * Resolves a snapshot path from operator-controlled places only.
 * @returns {{path: string|null, source: 'env'|'operator-config'|null, projectLocalIgnored: string|null}}
 */
export function resolveOperatorSnapshot({ envVar, fileName, root = null, env = process.env }) {
  const local = root ? statePath(root, fileName) : null;
  const projectLocalIgnored = local && existsSync(local) ? local : null;
  if (env[envVar]) return { path: env[envVar], source: 'env', projectLocalIgnored };
  const cfg = join(operatorConfigDir(env), fileName);
  if (isRegularFile(cfg)) return { path: cfg, source: 'operator-config', projectLocalIgnored };
  return { path: null, source: null, projectLocalIgnored };
}

/** The sentence added to a "no snapshot" reason when the project carried one that was deliberately ignored. */
export const IGNORED_NOTE = (fileName) => ` A ${fileName} inside the scanned project was IGNORED: a project cannot vouch for its own advisories (provide the snapshot through the environment variable or your per-user configuration directory).`;
