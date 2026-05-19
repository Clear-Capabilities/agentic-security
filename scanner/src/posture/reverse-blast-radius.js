// FR-ADV-5 — Reverse blast-radius for dependencies.
//
// "If `lodash` is RCE'd tomorrow, what's our exposure?" — pre-compute a
// reverse-reachability map for every direct dependency. The map keys on
// package name and lists the source files that import the package, the
// API surfaces they expose (HTTP routes that ultimately call into the dep),
// and the data classes those routes touch.
//
// Composes with:
//   - SCA pipeline: when a KEV-listed CVE matches a dep, the reverse map
//     gives an instant impact summary without a re-scan.
//   - crown-jewels.js: routes scored as crown-jewel that pull in the dep
//     elevate the dep's risk score.
//
// Output shape:
//   {
//     [pkgName]: {
//       directImporters: [{ file, count, exampleSymbols: [...] }],
//       routeExposure: [{ route, file }],
//       crownJewelTouch: 0..1,
//     }
//   }

import { mapCrownJewels } from './crown-jewels.js';

const IMPORT_RES = [
  /(?:^|\n)\s*import\s+(?:[\w*${},\s]+\s+from\s+)?["']([^"'.][^"']+)["']/g,
  /\brequire\(\s*["']([^"'.][^"']+)["']\s*\)/g,
];

const ROUTE_RES = [
  /app\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /router\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

function packageNameFromSpec(spec) {
  if (spec.startsWith('node:') || spec.startsWith('bun:')) return null;
  return spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
}

function extractImports(text) {
  const pkgs = new Map();
  if (!text || typeof text !== 'string') return pkgs;
  for (const re of IMPORT_RES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      const pkg = packageNameFromSpec(m[1]);
      if (!pkg) continue;
      pkgs.set(pkg, (pkgs.get(pkg) || 0) + 1);
    }
  }
  return pkgs;
}

function extractRoutesInFile(text) {
  const out = [];
  if (!text || typeof text !== 'string') return out;
  for (const re of ROUTE_RES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) out.push(m[1]);
  }
  return out;
}

export function buildReverseBlastRadius(fileContents) {
  const map = {};
  if (!fileContents || typeof fileContents !== 'object') return map;
  const crownMap = mapCrownJewels(fileContents);
  for (const [fp, text] of Object.entries(fileContents)) {
    const pkgs = extractImports(text);
    if (!pkgs.size) continue;
    const routes = extractRoutesInFile(text);
    const crownScore = crownMap[fp]?.score || 0;
    for (const [pkg, count] of pkgs) {
      if (!map[pkg]) map[pkg] = { directImporters: [], routeExposure: [], crownJewelTouch: 0 };
      map[pkg].directImporters.push({ file: fp, count });
      for (const route of routes) map[pkg].routeExposure.push({ route, file: fp });
      if (crownScore > map[pkg].crownJewelTouch) map[pkg].crownJewelTouch = crownScore;
    }
  }
  // Compact: cap each list at 25 entries for SARIF embedding.
  for (const pkg of Object.keys(map)) {
    map[pkg].directImporters = map[pkg].directImporters.slice(0, 25);
    map[pkg].routeExposure = map[pkg].routeExposure.slice(0, 25);
  }
  return map;
}

// Annotate SCA findings with reverse-blast context — when a CVE finding's
// `package` matches a known dep, the SCA finding gets `reverseExposure`.
export function annotateScaReverseBlast(findings, fileContents) {
  if (!Array.isArray(findings)) return findings;
  const map = buildReverseBlastRadius(fileContents || {});
  if (!Object.keys(map).length) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const pkg = f.package || f.dependency || f.pkg;
    if (!pkg || !map[pkg]) continue;
    f.reverseExposure = {
      importerCount: map[pkg].directImporters.length,
      routeCount: map[pkg].routeExposure.length,
      crownJewelTouch: Number(map[pkg].crownJewelTouch.toFixed(2)),
      sampleImporters: map[pkg].directImporters.slice(0, 5).map(i => i.file),
      sampleRoutes: map[pkg].routeExposure.slice(0, 5).map(r => r.route),
    };
  }
  return findings;
}
