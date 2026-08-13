export const id = 700;
export const ids = [700];
export const modules = {

/***/ 1700:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   validateOsvFunctionsExist: () => (/* binding */ validateOsvFunctionsExist)
/* harmony export */ });
/* unused harmony export extractPythonPackageFunctions */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1421);
/* harmony import */ var _ir_parser_py_cst_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(682);
// Python package function extraction via the CST parser.
//
// Locates an installed Python package in site-packages or .venv,
// parses its source files via the Python CST parser, and returns
// a map of exported function names. Used by markUsedVulnFunctions
// to validate that OSV-named vulnerable functions actually exist
// in the installed version.






const VENV_DIRS = ['.venv', 'venv', '.env', 'env'];

function _findSitePackages(scanRoot) {
  for (const vdir of VENV_DIRS) {
    const base = node_path__WEBPACK_IMPORTED_MODULE_1__.join(scanRoot || '.', vdir);
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(base)) continue;
    const lib = node_path__WEBPACK_IMPORTED_MODULE_1__.join(base, 'lib');
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(lib)) continue;
    const pydirs = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(lib).filter(d => d.startsWith('python'));
    for (const pydir of pydirs) {
      const sp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(lib, pydir, 'site-packages');
      if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(sp)) return sp;
    }
  }
  // Fallback: ask python3 directly
  try {
    const out = (0,node_child_process__WEBPACK_IMPORTED_MODULE_2__.execFileSync)('python3', ['-c', 'import site; print(site.getsitepackages()[0])'], {
      encoding: 'utf8', timeout: 5000,
    }).trim();
    if (out && node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(out)) return out;
  } catch { /* no python3 or no site-packages */ }
  return null;
}

function _findPackageDir(sitePackages, packageName) {
  if (!sitePackages) return null;
  const normalized = packageName.replace(/-/g, '_').toLowerCase();
  const candidates = [
    normalized,
    packageName.toLowerCase(),
    packageName,
  ];
  for (const name of candidates) {
    const dir = node_path__WEBPACK_IMPORTED_MODULE_1__.join(sitePackages, name);
    if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(dir) && node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(dir).isDirectory()) return dir;
  }
  return null;
}

function _readPyFilesFromDir(dir, maxFiles = 50) {
  const entries = [];
  try {
    const files = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { recursive: true })
      .filter(f => f.endsWith('.py'))
      .slice(0, maxFiles);
    for (const f of files) {
      const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, f);
      try {
        const content = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8');
        if (content.length < 1_000_000) {
          entries.push({ file: f, content });
        }
      } catch { /* skip unreadable files */ }
    }
  } catch { /* dir not readable */ }
  return entries;
}

function extractPythonPackageFunctions(packageName, scanRoot) {
  const cap = (0,_ir_parser_py_cst_js__WEBPACK_IMPORTED_MODULE_3__/* .probePythonAvailable */ .w4)();
  if (!cap.ok) return null;

  const sitePackages = _findSitePackages(scanRoot);
  const pkgDir = _findPackageDir(sitePackages, packageName);
  if (!pkgDir) return null;

  const pyFiles = _readPyFilesFromDir(pkgDir);
  if (!pyFiles.length) return null;

  const batch = (0,_ir_parser_py_cst_js__WEBPACK_IMPORTED_MODULE_3__/* .parsePythonFilesBatch */ .H2)(pyFiles);
  if (!batch || !Array.isArray(batch)) return null;

  const functionMap = new Map();
  for (const fileIR of batch) {
    if (!fileIR || !fileIR.functions) continue;
    for (const fn of fileIR.functions) {
      if (fn.name && !fn.name.startsWith('_')) {
        functionMap.set(fn.name, {
          file: fileIR.file,
          line: fn.line,
          qid: fn.qid,
          params: fn.params,
        });
      }
    }
  }
  return functionMap;
}

function validateOsvFunctionsExist(packageName, osvFunctions, scanRoot) {
  if (!osvFunctions || !osvFunctions.length) return { validated: [], missing: [] };
  const fnMap = extractPythonPackageFunctions(packageName, scanRoot);
  if (!fnMap) return { validated: osvFunctions, missing: [] };
  const validated = [];
  const missing = [];
  for (const fn of osvFunctions) {
    const shortFn = fn.includes('.') ? fn.split('.').pop() : fn;
    if (fnMap.has(shortFn) || fnMap.has(fn)) {
      validated.push(shortFn);
    } else {
      missing.push(fn);
    }
  }
  return { validated, missing };
}


/***/ })

};
