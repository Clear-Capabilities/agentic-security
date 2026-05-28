// Python package function extraction via the CST parser.
//
// Locates an installed Python package in site-packages or .venv,
// parses its source files via the Python CST parser, and returns
// a map of exported function names. Used by markUsedVulnFunctions
// to validate that OSV-named vulnerable functions actually exist
// in the installed version.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parsePythonFilesBatch, probePythonAvailable } from '../ir/parser-py-cst.js';

const VENV_DIRS = ['.venv', 'venv', '.env', 'env'];

function _findSitePackages(scanRoot) {
  for (const vdir of VENV_DIRS) {
    const base = path.join(scanRoot || '.', vdir);
    if (!fs.existsSync(base)) continue;
    const lib = path.join(base, 'lib');
    if (!fs.existsSync(lib)) continue;
    const pydirs = fs.readdirSync(lib).filter(d => d.startsWith('python'));
    for (const pydir of pydirs) {
      const sp = path.join(lib, pydir, 'site-packages');
      if (fs.existsSync(sp)) return sp;
    }
  }
  // Fallback: ask python3 directly
  try {
    const out = execFileSync('python3', ['-c', 'import site; print(site.getsitepackages()[0])'], {
      encoding: 'utf8', timeout: 5000,
    }).trim();
    if (out && fs.existsSync(out)) return out;
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
    const dir = path.join(sitePackages, name);
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) return dir;
  }
  return null;
}

function _readPyFilesFromDir(dir, maxFiles = 50) {
  const entries = [];
  try {
    const files = fs.readdirSync(dir, { recursive: true })
      .filter(f => f.endsWith('.py'))
      .slice(0, maxFiles);
    for (const f of files) {
      const fp = path.join(dir, f);
      try {
        const content = fs.readFileSync(fp, 'utf8');
        if (content.length < 1_000_000) {
          entries.push({ file: f, content });
        }
      } catch { /* skip unreadable files */ }
    }
  } catch { /* dir not readable */ }
  return entries;
}

export function extractPythonPackageFunctions(packageName, scanRoot) {
  const cap = probePythonAvailable();
  if (!cap.ok) return null;

  const sitePackages = _findSitePackages(scanRoot);
  const pkgDir = _findPackageDir(sitePackages, packageName);
  if (!pkgDir) return null;

  const pyFiles = _readPyFilesFromDir(pkgDir);
  if (!pyFiles.length) return null;

  const batch = parsePythonFilesBatch(pyFiles);
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

export function validateOsvFunctionsExist(packageName, osvFunctions, scanRoot) {
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
