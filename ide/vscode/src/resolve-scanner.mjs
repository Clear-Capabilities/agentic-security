// Where the VS Code extension looks for the scanner bundle.
//
// Extracted from extension.ts so it can be TESTED. It previously lived inline,
// depended on `vscode.workspace.getConfiguration`, and was therefore
// unreachable from any test — which is how it shipped with a hardcoded
// `'0.1.0'` version segment in the plugin-cache path.
//
// That path never exists. Claude Code caches a plugin under its PLUGIN
// version (`.../agentic-security/0.139.1/…`), which tracks
// `.claude-plugin/plugin.json` and has never been `0.1.0` — the `0.1.0` was
// the VS Code extension's OWN version from `ide/vscode/package.json`, pasted
// into the wrong path. The user-visible symptom was the fallback failing
// silently and the extension reporting "scanner not found. Set
// agenticSecurity.scannerPath in settings." on every install, forever.
//
// This is the exact defect class PRD F11.1 names: the engine is gated by four
// benches while the surfaces that carry it to users are not gated at all, so a
// broken IDE extension ships silently.
//
// Kept as plain JS, with every input passed in rather than read from the
// ambient environment, so the whole thing is a pure function of its arguments
// and a test can drive it against a synthesized directory tree.
import * as fs from 'node:fs';
import * as path from 'node:path';

const CACHE_SEGMENTS = ['.claude', 'plugins', 'cache', 'clearcapabilities', 'agentic-security'];
const BUNDLE_SEGMENTS = ['scanner', 'dist', 'agentic-security.mjs'];

// Descending semver-ish order. Segments compare numerically so 0.140.0 sorts
// above 0.99.0 — a lexical sort gets that backwards, and the cache directory
// on a long-lived install holds every version the user has ever run.
function compareVersionsDesc(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10));
  const pb = String(b).split('.').map((n) => parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number.isFinite(pa[i]) ? pa[i] : -1;
    const y = Number.isFinite(pb[i]) ? pb[i] : -1;
    if (x !== y) return y - x;
  }
  return String(b).localeCompare(String(a));
}

/**
 * @param {object} opts
 * @param {string} [opts.explicit]     agenticSecurity.scannerPath, if the user set one
 * @param {string} [opts.pluginRoot]   CLAUDE_PLUGIN_ROOT, set when running inside the plugin
 * @param {string} [opts.home]         the user's home directory
 * @param {string} [opts.workspace]    the open workspace folder, for a local npm install
 * @param {(p: string) => boolean} [opts.exists]  injected for testing
 * @param {(p: string) => string[]} [opts.readdir] injected for testing
 * @returns {{ path: string, source: string } | null}
 */
export function resolveScanner(opts = {}) {
  const exists = opts.exists || ((p) => fs.existsSync(p));
  const readdir = opts.readdir || ((p) => fs.readdirSync(p));

  // 1. The user said where it is. Their answer wins over every heuristic.
  if (opts.explicit && exists(opts.explicit)) {
    return { path: opts.explicit, source: 'setting' };
  }

  // 2. Running inside the Claude Code plugin: the root is handed to us and
  //    needs no version guessing at all. This is the case the old code should
  //    have used first and did not have.
  if (opts.pluginRoot) {
    const p = path.join(opts.pluginRoot, ...BUNDLE_SEGMENTS);
    if (exists(p)) return { path: p, source: 'plugin-root' };
  }

  // 3. The plugin cache, NEWEST version first. The version segment is
  //    discovered, never hardcoded — hardcoding it is the bug this replaces.
  if (opts.home) {
    const cacheDir = path.join(opts.home, ...CACHE_SEGMENTS);
    let versions = [];
    try { versions = readdir(cacheDir); } catch { versions = []; }
    for (const v of versions.slice().sort(compareVersionsDesc)) {
      const p = path.join(cacheDir, v, ...BUNDLE_SEGMENTS);
      if (exists(p)) return { path: p, source: `plugin-cache@${v}` };
    }
  }

  // 4. Installed as an ordinary npm dependency of the open project.
  if (opts.workspace) {
    const p = path.join(opts.workspace, 'node_modules', 'agentic-security', 'dist', 'agentic-security.mjs');
    if (exists(p)) return { path: p, source: 'workspace-node-modules' };
  }

  return null;
}
