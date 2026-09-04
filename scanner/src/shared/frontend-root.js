// frontend-root.js — locates the Data Flow Explorer's `frontend/` assets
// (index.html/src/styles) regardless of whether this code is running:
//   - unbundled, straight out of scanner/src/ or scanner/scripts/ (dev/test —
//     frontend/ is a monorepo sibling of scanner/, 2-3 levels up), or
//   - bundled by `npm run build` (ncc splits a dynamic import() into its own
//     chunk file physically written into scanner/dist/, so import.meta.url
//     inside that chunk reflects dist/'s own location, not the original
//     source file's — a fixed relative-levels-up path that was correct for
//     one depth breaks silently at the other), or
//   - installed from the published npm package, where the build copies
//     frontend/'s servable files into scanner/dist/frontend/ (a sibling of
//     the chunk file itself, i.e. 0 levels up) — see scripts/copy-frontend.mjs.
//
// Rather than hardcode one of those depths (the bug this file fixes: every
// consumer used to hardcode the dev-only depth), search upward from the
// caller's own directory and take the first candidate that actually has a
// frontend/index.html on disk. Never guessed silently past that — a caller
// with no match anywhere gets a clear, actionable error instead of a
// downstream ENOENT/404 with no indication why.

import * as fs from 'node:fs';
import * as path from 'node:path';

const MAX_LEVELS_UP = 4;

/**
 * @param {string} startDir - `path.dirname(fileURLToPath(import.meta.url))`
 *   of the CALLING module (not this file) — each caller's own bundled/
 *   unbundled location determines which candidate depth resolves.
 * @returns {string} absolute path to a real `frontend/` directory containing
 *   `index.html`.
 * @throws if no candidate directory up to MAX_LEVELS_UP contains one.
 */
export function resolveFrontendRoot(startDir) {
  const tried = [];
  for (let up = 0; up <= MAX_LEVELS_UP; up++) {
    const candidate = path.resolve(startDir, ...Array(up).fill('..'), 'frontend');
    tried.push(candidate);
    // Every caller invokes resolveFrontendRoot() once, at module-load time,
    // to compute a top-level FRONTEND_ROOT const (see static-assets.js /
    // generate-html-report.mjs) — never per-request inside the explore
    // server's request handler. At most MAX_LEVELS_UP+1 (5) sync stat calls
    // at process startup is not a request-path DoS surface.
    if (fs.existsSync(path.join(candidate, 'index.html'))) return candidate; // agentic-security-ignore: dos-sync-io
  }
  throw new Error(
    `resolveFrontendRoot: no frontend/index.html found searching up from ${startDir}. ` +
    `Tried: ${tried.join(', ')}. If you're running from a source checkout, run \`npm run build\` ` +
    `first (it copies frontend/ into scanner/dist/frontend/); if you're running the published ` +
    `package, this indicates a packaging defect — report it.`
  );
}
