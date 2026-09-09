#!/usr/bin/env node
// npm lifecycle "prepare" script — runs after every `npm install`/`npm ci`,
// including a published consumer's install of this package as a dependency.
// Everything here MUST no-op cleanly when that's the case (nothing here is
// meant for a consumer, and nothing here may assume the sibling files it
// checks for actually exist).
//
// Two source-repo-only steps, both guarded on "is this actually a checkout
// of this repo, not a consumer's node_modules":
//
// 1. Install the local git pre-push hook (scripts/pre-push-gate.mjs
//    --install-hook) — see that script for what it does.
// 2. Vendor java-parser's resolved dependency closure into vendor/java-parser/
//    (scripts/vendor-java-parser.mjs) so `src/` is immediately usable via the
//    "#java-parser" imports alias right after install — not only after a
//    separate `npm run build`. This gap is exactly what broke CI for 0.149.3:
//    jobs that run `npm ci` and then use `src/` directly (bench/cve-replay,
//    determinism-attest) never ran `npm run build` first, so vendor/ never
//    existed and every Java-parsing import threw ERR_MODULE_NOT_FOUND.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..');
const REPO_ROOT_MARKER = path.join(SCANNER, '..', 'scripts', 'pre-push-gate.mjs');

if (!fs.existsSync(REPO_ROOT_MARKER)) {
  // Installed as a dependency (or any context outside this repo's own
  // checkout) — nothing in this file applies. Exit quietly and successfully.
  process.exit(0);
}

execFileSync(process.execPath, [REPO_ROOT_MARKER, '--install-hook'], { stdio: 'inherit' });
execFileSync(process.execPath, [path.join(HERE, 'vendor-java-parser.mjs')], { stdio: 'inherit' });
