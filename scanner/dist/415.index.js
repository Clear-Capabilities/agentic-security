export const id = 415;
export const ids = [415];
export const modules = {

/***/ 3415:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   extractImagePackages: () => (/* binding */ extractImagePackages)
/* harmony export */ });
/* unused harmony exports parseDpkgStatus, parseApkInstalled */
// R8 (PRD §5) — container-image OS-package inventory.
//
// container.js reads the Dockerfile (FROM + apt/apk install lines). This reads
// the ACTUAL installed-package databases from an extracted image filesystem
// (or the host), catching packages baked into the base image that the
// Dockerfile never names. Components flow into the existing OSV pipeline + SBOM.
//
// Pure parsers (unit-tested) + a path-matching extractor. No daemon; reads the
// package-DB files that appear when an image layer/tarball is unpacked.

// Debian/Ubuntu: /var/lib/dpkg/status — RFC822-style blocks separated by blank
// lines. Only "install ok installed" entries count (not removed/config-files).
function parseDpkgStatus(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const name = (block.match(/^Package:\s*(.+)$/m) || [])[1];
    const version = (block.match(/^Version:\s*(.+)$/m) || [])[1];
    const status = (block.match(/^Status:\s*(.+)$/m) || [])[1] || '';
    if (!name || !version) continue;
    if (!/\binstalled\b/.test(status)) continue;
    out.push({ name: name.trim(), version: version.trim(), ecosystem: 'Debian' });
  }
  return out;
}

// Alpine: /lib/apk/db/installed — blocks separated by blank lines; P:=name V:=version.
function parseApkInstalled(text) {
  const out = [];
  for (const block of String(text || '').split(/\n\s*\n/)) {
    const name = (block.match(/^P:(.+)$/m) || [])[1];
    const version = (block.match(/^V:(.+)$/m) || [])[1];
    if (!name || !version) continue;
    out.push({ name: name.trim(), version: version.trim(), ecosystem: 'Alpine' });
  }
  return out;
}

const _PURL = { Debian: (n, v) => `pkg:deb/debian/${n}@${v}`, Alpine: (n, v) => `pkg:apk/alpine/${n}@${v}` };

// File-path tells for an unpacked image. Match on path suffix so it works
// whether the scan root is the rootfs or a subdirectory of it.
function _dbKind(path) {
  const p = path.replace(/\\/g, '/');
  if (/(?:^|\/)var\/lib\/dpkg\/status$/.test(p)) return 'dpkg';
  if (/(?:^|\/)lib\/apk\/db\/installed$/.test(p)) return 'apk';
  return null;
}

/**
 * Extract OS-package components from any image package-DBs present in the scanned
 * files. Returns components in the engine's component shape so they ride the
 * existing OSV/SBOM pipeline. De-dups by ecosystem:name:version.
 */
function extractImagePackages(fileContents) {
  const comps = [];
  const seen = new Set();
  for (const [file, content] of Object.entries(fileContents || {})) {
    const kind = _dbKind(file);
    if (!kind) continue;
    const pkgs = kind === 'dpkg' ? parseDpkgStatus(content) : parseApkInstalled(content);
    for (const p of pkgs) {
      const key = `${p.ecosystem}:${p.name}:${p.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name: p.name, version: p.version, group: '', ecosystem: p.ecosystem,
        purl: (_PURL[p.ecosystem] || (() => null))(p.name, p.version),
        filePath: file, isUnpinned: false, isTransitive: false, isOsPackage: true,
        scope: 'required', reachable: true,
      });
    }
  }
  return comps;
}


/***/ })

};
