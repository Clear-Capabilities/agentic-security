// Builds an npm lockfile (version 3) for a dependency tree of local tarballs, with real sha512 integrities. For the dependency repair
// tests: a candidate's lockfile is data the verifier checks, so the tests write lockfiles exactly as npm would record them.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * @param {string} root  project root holding the tarballs
 * @param {{name:string, version:string}} project
 * @param {Record<string,string>} deps  manifest dependencies (name -> range)
 * @param {Record<string,{version:string, tarball:string, dependencies?:Record<string,string>}>} installed  lockfile path -> entry
 */
export function npmLock(root, project, deps, installed) {
  const packages = { '': { name: project.name, version: project.version, dependencies: { ...deps } } };
  for (const [p, e] of Object.entries(installed)) {
    const bytes = fs.readFileSync(path.join(root, e.tarball));
    packages[p] = { version: e.version, resolved: `file:${e.tarball}`, integrity: `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`, ...(e.dependencies ? { dependencies: e.dependencies } : {}) };
  }
  return `${JSON.stringify({ name: project.name, version: project.version, lockfileVersion: 3, requires: true, packages }, null, 2)}\n`;
}
