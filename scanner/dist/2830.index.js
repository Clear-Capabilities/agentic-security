export const id = 2830;
export const ids = [2830];
export const modules = {

/***/ 2830:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   discoverHarnessConfigs: () => (/* binding */ discoverHarnessConfigs),
/* harmony export */   summarizeHarnessPresence: () => (/* binding */ summarizeHarnessPresence)
/* harmony export */ });
/* unused harmony export HARNESS_DIRS */
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1455);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(8161);
// Multi-harness configuration discovery.
//
// Finds every agent-harness configuration directory the user has, both at
// the project root AND under ~/. The discovered files feed the
// claude-settings / claude-md-prompt-injection / claude-hook-injection
// detectors so we audit Claude / Cursor / Codex / Gemini / Kiro / OpenCode /
// Trae / Qwen / Zed / Continue / Aider with one sweep.
//
// Used by the `/scan --harness` mode.





const HARNESS_DIRS = [
  '.claude', '.cursor', '.codex', '.gemini', '.kiro',
  '.opencode', '.trae', '.qwen', '.zed', '.continue', '.aider',
  '.codebuddy', '.copilot',
];

const HARNESS_FILES = [
  // settings + permissions
  'settings.json', 'settings.local.json', 'config.json',
  // instruction files (lifted into context every session)
  'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'CURSOR.md', 'CODEX.md',
  'KIRO.md', 'QWEN.md', 'TRAE.md', 'OPENCODE.md', 'SYSTEM_PROMPT.md',
  // mcp
  'mcp.json', '.mcp.json', 'mcp_servers.json', 'claude_desktop_config.json',
  // hooks
  'hooks.json', 'hooks.yml', 'hooks.yaml',
];

const HARNESS_SUBDIRS = ['agents', 'skills', 'commands', 'hooks', 'rules'];

const MAX_FILE_SIZE = 1_000_000;

async function _readSafe(fp) {
  try {
    const stat = await node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.stat(fp);
    if (stat.size > MAX_FILE_SIZE) return null;
    return await node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.readFile(fp, 'utf8');
  } catch { return null; }
}

async function _walkHarnessDir(harnessRoot, harnessName, out) {
  // Top-level config files.
  for (const fn of HARNESS_FILES) {
    const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(harnessRoot, fn);
    const content = await _readSafe(fp);
    if (content !== null) out[fp] = content;
  }
  // Subdirs holding instruction-style files.
  for (const sub of HARNESS_SUBDIRS) {
    const dp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(harnessRoot, sub);
    try {
      const entries = await node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.readdir(dp, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isFile()) continue;
        if (!/\.(?:md|json|yaml|yml)$/i.test(e.name)) continue;
        const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dp, e.name);
        const content = await _readSafe(fp);
        if (content !== null) out[fp] = content;
      }
    } catch { /* dir does not exist — fine */ }
  }
  // Project-root CLAUDE.md / AGENTS.md (some users put them outside .claude/).
  // Only walked when the harness is .claude.
  void harnessName;
}

// Discover harness configs at one of:
//   1. The project root (e.g. /path/to/repo/.claude, /path/to/repo/.cursor)
//   2. Home directory (e.g. ~/.claude, ~/.cursor) — opt-in via includeHome=true
async function discoverHarnessConfigs(projectRoot, opts = {}) {
  const includeHome = !!opts.includeHome;
  const out = {};

  // Project-rooted instruction files commonly placed at repo root.
  for (const fn of ['CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'CURSOR.md', 'CODEX.md', 'KIRO.md', 'QWEN.md', 'TRAE.md', 'OPENCODE.md']) {
    const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(projectRoot, fn);
    const content = await _readSafe(fp);
    if (content !== null) out[fp] = content;
  }

  for (const dir of HARNESS_DIRS) {
    const harnessRoot = node_path__WEBPACK_IMPORTED_MODULE_1__.join(projectRoot, dir);
    try { await node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.access(harnessRoot); } catch { continue; }
    await _walkHarnessDir(harnessRoot, dir, out);
  }

  if (includeHome) {
    const home = node_os__WEBPACK_IMPORTED_MODULE_2__.homedir();
    if (home) {
      for (const dir of HARNESS_DIRS) {
        const harnessRoot = node_path__WEBPACK_IMPORTED_MODULE_1__.join(home, dir);
        try { await node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.access(harnessRoot); } catch { continue; }
        await _walkHarnessDir(harnessRoot, dir, out);
      }
    }
  }

  return out;
}

// Inventory of which harnesses are present (for grade / summary).
function summarizeHarnessPresence(fileContents) {
  const present = new Set();
  for (const fp of Object.keys(fileContents || {})) {
    const m = /\.(claude|cursor|codex|gemini|kiro|opencode|trae|qwen|zed|continue|aider|codebuddy|copilot)[\\/]/.exec(fp);
    if (m) present.add(m[1]);
  }
  return [...present].sort();
}


/***/ })

};
