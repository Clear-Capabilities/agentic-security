#!/usr/bin/env node
// copy-frontend.mjs — build step. Copies the Data Flow Explorer frontend's
// servable files (frontend/, a repo-root sibling of scanner/, so it's never
// published as part of the scanner npm package on its own) into
// scanner/dist/frontend/, which IS shipped (package.json's `files` already
// includes the whole `dist/` tree). `explore` (static-assets.js) and
// `dataflow export --format html` (generate-html-report.mjs) both locate
// this copy at runtime via src/shared/frontend-root.js's search-upward
// resolver — see that file for why a fixed relative path breaks under ncc
// bundling.
//
// Mirrors static-assets.js's own servable-file allowlist exactly (same
// three rules, so nothing gets shipped that couldn't be served, and nothing
// servable gets left out): `index.html`; `src/**/*.js` (nested subdirs
// allowed); top-level `styles/*.css` only (no nested subdirs). Deliberately
// does NOT copy frontend/README.md, frontend/package.json, frontend/test/,
// frontend/scripts/ — none of those are ever served, and shipping them
// would just be needless bytes in the published package.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const SRC_FRONTEND = path.join(REPO_ROOT, 'frontend');
const DEST_FRONTEND = path.resolve(HERE, '..', 'dist', 'frontend');

function copyFile(srcAbs, destAbs) {
  fs.mkdirSync(path.dirname(destAbs), { recursive: true });
  fs.copyFileSync(srcAbs, destAbs);
}

function copyJsTreeRecursive(srcDir, destDir) {
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const srcAbs = path.join(srcDir, entry.name);
    const destAbs = path.join(destDir, entry.name);
    if (entry.isDirectory()) {
      copyJsTreeRecursive(srcAbs, destAbs);
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      copyFile(srcAbs, destAbs);
    }
  }
}

function main() {
  if (!fs.existsSync(path.join(SRC_FRONTEND, 'index.html'))) {
    throw new Error(`copy-frontend: no frontend/index.html found at ${SRC_FRONTEND} — run from a full source checkout`);
  }
  fs.rmSync(DEST_FRONTEND, { recursive: true, force: true });

  copyFile(path.join(SRC_FRONTEND, 'index.html'), path.join(DEST_FRONTEND, 'index.html'));

  const stylesSrc = path.join(SRC_FRONTEND, 'styles');
  for (const entry of fs.readdirSync(stylesSrc, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.css')) {
      copyFile(path.join(stylesSrc, entry.name), path.join(DEST_FRONTEND, 'styles', entry.name));
    }
  }

  copyJsTreeRecursive(path.join(SRC_FRONTEND, 'src'), path.join(DEST_FRONTEND, 'src'));

  process.stdout.write(`copy-frontend: copied frontend/ -> ${path.relative(REPO_ROOT, DEST_FRONTEND)}\n`);
}

main();
