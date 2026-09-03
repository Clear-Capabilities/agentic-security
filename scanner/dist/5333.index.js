export const id = 5333;
export const ids = [5333];
export const modules = {

/***/ 5333:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   applyScaUpgrade: () => (/* binding */ applyScaUpgrade),
/* harmony export */   planScaUpgrade: () => (/* binding */ planScaUpgrade)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1455);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(7598);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(1421);
/* harmony import */ var node_util__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(7975);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(1174);
// SCA upgrade engine: dry-run plan + worktree-isolated apply.
//
// Phase 3 / Item 5 of the SCA improvement plan. The MCP `apply_fix` path
// refuses to write manifest files (package.json, *-lock.*, poetry.lock,
// Cargo.lock, etc.) for safety. SCA findings need a separate path that:
//   1. Generates an upgrade *plan* via the ecosystem's native dry-run
//      command (npm install --dry-run, pip install --dry-run, etc.).
//   2. Applies the upgrade via the package manager itself, with a backup
//      + test-gate so a peer-dep break or test regression rolls back.
//
// Caller pattern: plan first (read-only), inspect the breaking-change
// flag / peer warnings, then apply with confirm:true.









const execFileAsync = (0,node_util__WEBPACK_IMPORTED_MODULE_5__.promisify)(node_child_process__WEBPACK_IMPORTED_MODULE_4__.execFile);

// Per-ecosystem command/manifest map. Add ecosystems by extending this
// table — every other place in the module reads it.
const ECOSYSTEM = {
  npm: {
    manifests: ['package.json', 'package-lock.json'],
    altManifests: [['yarn.lock'], ['pnpm-lock.yaml']],
    dryRun: (pkg, ver) => ({ cmd: 'npm', args: ['install', `${pkg}@${ver}`, '--dry-run', '--json'] }),
    apply:  (pkg, ver) => ({ cmd: 'npm', args: ['install', `${pkg}@${ver}`, '--save'] }),
    parseDryRun(stdout) {
      try {
        const j = JSON.parse(stdout);
        const peerDeps = Array.isArray(j.warnings) ? j.warnings.filter(w => /peer dep/i.test(w)) : [];
        const transitiveImpact = (j.added || []).length + (j.updated || []).length + (j.removed || []).length;
        return { peerDeps, transitiveImpact, rawSummary: { added: (j.added || []).length, updated: (j.updated || []).length, removed: (j.removed || []).length } };
      } catch { return { peerDeps: [], transitiveImpact: 0, rawSummary: null }; }
    },
  },
  pypi: {
    manifests: ['requirements.txt', 'pyproject.toml'],
    altManifests: [['poetry.lock'], ['Pipfile.lock']],
    dryRun: (pkg, ver) => ({ cmd: 'pip', args: ['install', '--dry-run', `${pkg}==${ver}`] }),
    apply:  (pkg, ver) => ({ cmd: 'pip', args: ['install', '--upgrade', `${pkg}==${ver}`] }),
    parseDryRun() {
      // pip --dry-run output is human-readable; we don't parse it for v1.
      return { peerDeps: [], transitiveImpact: 0, rawSummary: null };
    },
  },
  cargo: {
    manifests: ['Cargo.toml', 'Cargo.lock'],
    altManifests: [],
    dryRun: (pkg, _ver) => ({ cmd: 'cargo', args: ['update', '--package', pkg, '--dry-run'] }),
    apply:  (pkg, _ver) => ({ cmd: 'cargo', args: ['update', '--package', pkg] }),
    parseDryRun() { return { peerDeps: [], transitiveImpact: 0, rawSummary: null }; },
  },
  golang: {
    manifests: ['go.mod', 'go.sum'],
    altManifests: [],
    dryRun: (_pkg, _ver) => null,   // `go get` has no dry-run flag; we skip dry-run in v1.
    apply:  (pkg, ver) => ({ cmd: 'go', args: ['get', `${pkg}@v${ver}`] }),
    parseDryRun() { return { peerDeps: [], transitiveImpact: 0, rawSummary: null }; },
  },
  // Other ecosystems (rubygems, packagist, pub, maven) return a structured
  // "manual" plan in v1 — no native dry-run + the install side-effects
  // (gem build artifacts, composer cache) are easier for the user to
  // confirm interactively.
};

function _majorVersion(v) {
  const m = String(v || '').match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function _detectTestCommand(scanRoot) {
  try {
    const pkg = node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, 'package.json');
    if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(pkg)) {
      const j = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(pkg, 'utf8'));
      if (j.scripts?.test && !/no test specified/i.test(j.scripts.test)) {
        return { cmd: 'npm', args: ['test'] };
      }
    }
  } catch {}
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, 'Cargo.toml'))) return { cmd: 'cargo', args: ['test'] };
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, 'go.mod'))) return { cmd: 'go', args: ['test', './...'] };
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, 'pyproject.toml'))) return { cmd: 'pytest', args: [] };
  return null;
}

// Produce a structured upgrade plan WITHOUT modifying anything on disk.
// Safe to call repeatedly; runs the ecosystem's --dry-run command.
async function planScaUpgrade({ scanRoot, finding }) {
  if (!finding || finding.type !== 'vulnerable_dep') {
    return { ok: false, reason: 'not a vulnerable_dep finding' };
  }
  const eco = ECOSYSTEM[finding.ecosystem];
  if (!eco) {
    return {
      ok: true,
      mode: 'manual',
      reason: `ecosystem '${finding.ecosystem}' has no automated upgrade in v1`,
      package: finding.name, currentVersion: finding.version,
      targetVersion: (finding.fixedVersions && finding.fixedVersions[0]) || null,
      command: null,
    };
  }
  const target = (finding.fixedVersions && finding.fixedVersions[0]) || null;
  if (!target) {
    return { ok: false, reason: 'no fixed version in OSV record' };
  }
  const isBreaking = (_majorVersion(target) ?? 0) > (_majorVersion(finding.version) ?? 0);
  const apply = eco.apply(finding.name, target);
  const dryRunSpec = eco.dryRun(finding.name, target);
  let peerDeps = [], transitiveImpact = 0, rawSummary = null, dryRunOk = null;
  if (dryRunSpec) {
    try {
      const r = await execFileAsync(dryRunSpec.cmd, dryRunSpec.args, {
        cwd: scanRoot, timeout: 60_000, maxBuffer: 8 * 1024 * 1024,
      });
      const parsed = eco.parseDryRun(r.stdout);
      peerDeps = parsed.peerDeps;
      transitiveImpact = parsed.transitiveImpact;
      rawSummary = parsed.rawSummary;
      dryRunOk = true;
    } catch (e) {
      // Dry-run failed (e.g. peer-dep resolution conflict). Surface the
      // error structurally so the caller can decide whether to proceed.
      dryRunOk = false;
      const stderr = (e && e.stderr) || (e && e.message) || '';
      peerDeps = /peer dep/i.test(stderr) ? [String(stderr).slice(0, 500)] : [];
    }
  }
  return {
    ok: true,
    mode: 'auto',
    ecosystem: finding.ecosystem,
    package: finding.name,
    currentVersion: finding.version,
    targetVersion: target,
    isBreaking,
    command: `${apply.cmd} ${apply.args.join(' ')}`,
    manifestFiles: eco.manifests,
    dryRun: { ok: dryRunOk, command: dryRunSpec ? `${dryRunSpec.cmd} ${dryRunSpec.args.join(' ')}` : null, peerDeps, transitiveImpact, rawSummary },
    testCommand: (() => { const t = _detectTestCommand(scanRoot); return t ? `${t.cmd} ${t.args.join(' ')}` : null; })(),
  };
}

// Apply the upgrade. Backs up affected manifests, runs the install, runs
// the project's test command if detected, and ROLLS BACK on failure.
// Audit-logged via the MCP audit layer at the call site.
async function applyScaUpgrade({ scanRoot, finding, runTests = true }) {
  const plan = await planScaUpgrade({ scanRoot, finding });
  if (!plan.ok) return { applied: false, reason: plan.reason };
  if (plan.mode === 'manual') {
    return { applied: false, reason: plan.reason, plan };
  }
  const eco = ECOSYSTEM[finding.ecosystem];
  const target = plan.targetVersion;

  // Backup pass — record original contents of every relevant manifest so
  // we can restore on test failure. node_modules / vendor dirs are NOT
  // backed up (too big); they'll be rebuilt by re-running the install on
  // restore.
  const stateDir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_6__.statePath)(scanRoot, 'sca-upgrade-history');
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(stateDir, { recursive: true });
  const upgradeId = node_crypto__WEBPACK_IMPORTED_MODULE_3__.randomBytes(8).toString('hex');
  const backups = {};
  for (const mf of eco.manifests) {
    const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, mf);
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(abs)) continue;
    const content = await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(abs, 'utf8');
    const backupPath = node_path__WEBPACK_IMPORTED_MODULE_2__.join(stateDir, `${upgradeId}-${mf.replace(/[\/\\]/g, '_')}.bak`);
    await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.writeFile(backupPath, content);
    backups[mf] = { abs, backupPath };
  }
  if (!Object.keys(backups).length) {
    return { applied: false, reason: `no ${finding.ecosystem} manifest files found in scan root` };
  }

  // Run the install.
  const apply = eco.apply(finding.name, target);
  let installOutput = '';
  try {
    const r = await execFileAsync(apply.cmd, apply.args, {
      cwd: scanRoot, timeout: 300_000, maxBuffer: 16 * 1024 * 1024,
    });
    installOutput = (r.stdout || '') + (r.stderr || '');
  } catch (e) {
    // Install failed; restore backups (manifests may have been touched).
    for (const { abs, backupPath } of Object.values(backups)) {
      try { await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.copyFile(backupPath, abs); } catch {}
    }
    return {
      applied: false,
      reason: `install failed: ${(e && e.message) || e}`.slice(0, 600),
      installOutput: ((e && e.stdout) || '').slice(0, 1500),
      restored: true,
      upgradeId,
    };
  }

  // Optionally run the project's test command. On failure, restore.
  let testResult = null;
  if (runTests) {
    const test = _detectTestCommand(scanRoot);
    if (test) {
      try {
        const r = await execFileAsync(test.cmd, test.args, {
          cwd: scanRoot, timeout: 600_000, maxBuffer: 16 * 1024 * 1024,
        });
        testResult = { ok: true, command: `${test.cmd} ${test.args.join(' ')}`, output: ((r.stdout || '') + (r.stderr || '')).slice(0, 2000) };
      } catch (e) {
        // Tests failed — restore manifests so the working tree is clean.
        for (const { abs, backupPath } of Object.values(backups)) {
          try { await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.copyFile(backupPath, abs); } catch {}
        }
        return {
          applied: false,
          reason: `tests failed after upgrade: ${(e && e.message) || e}`.slice(0, 300),
          testOutput: ((e && e.stdout) || '').slice(0, 2000),
          restored: true,
          upgradeId,
        };
      }
    }
  }

  // Success path — write a log entry so the user can audit / undo.
  const logEntry = {
    id: upgradeId,
    timestamp: new Date().toISOString(),
    ecosystem: finding.ecosystem,
    package: finding.name,
    from: finding.version,
    to: target,
    backups: Object.fromEntries(Object.entries(backups).map(([k, v]) => [k, v.backupPath])),
    testResult,
    isBreaking: plan.isBreaking,
    finding: { id: finding.id, osvId: finding.osvId, cveAliases: finding.cveAliases },
  };
  const logFp = node_path__WEBPACK_IMPORTED_MODULE_2__.join(stateDir, 'log.json');
  let log = [];
  try { log = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(logFp, 'utf8')); } catch {}
  log.push(logEntry);
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(logFp, JSON.stringify(log, null, 2));

  return {
    applied: true,
    upgradeId,
    package: finding.name,
    from: finding.version,
    to: target,
    isBreaking: plan.isBreaking,
    testResult,
    installOutput: installOutput.slice(0, 1500),
  };
}


/***/ })

};
