// Zip slip / archive path traversal detection. CWE-22 via archive extraction.
//
// Java vulnerable patterns:
//   - ZipEntry.getName() concatenated into a File / Files.write path
//   - new File(outDir, entry.getName())  without subsequent canonical-prefix check
//
// Python vulnerable patterns:
//   - tarfile.open(...).extractall()      pre-3.12 default behaviour (CVE-2007-4559)
//   - tarfile member.name joined to output path
//   - zipfile.extract(...) / extractall() without path normalization
//
// Node.js vulnerable patterns:
//   - unzipper / yauzl entry.path written to disk without sanitization
//   - tar package: tar.extract({cwd, ...}) with cwd inside writable area
//
// Safe shapes (suppress the finding for the file):
//   Java:    canonicalPath check, .normalize() then startsWith(outDir.toPath())
//   Python:  shutil._extract_member with explicit filter; tarfile filter='data'
//   Node:    sanitize-filename, path.resolve + startsWith check

const JAVA_ZIP_ENTRY_NAME_RE = /\b(?:ZipEntry|TarArchiveEntry|ArchiveEntry|entry)\s*\.\s*getName\s*\(\s*\)/g;
const JAVA_NEW_FILE_WITH_ENTRY_RE = /\bnew\s+File\s*\([^)]*\b(?:entry|zipEntry|tarEntry|archiveEntry)\s*\.\s*getName\s*\(\s*\)/g;
const JAVA_SAFE_CANONICAL_RE = /\b(?:getCanonicalPath|toRealPath|toAbsolutePath|normalize)\s*\(/;
const JAVA_SAFE_STARTSWITH_RE = /\.\s*startsWith\s*\(\s*[a-zA-Z_$][\w$.]*(?:\.\s*(?:getCanonicalPath|toPath|toAbsolutePath))?\s*\(?/;

const PY_TARFILE_EXTRACTALL_RE = /\btarfile\.[\w_]+\([^)]*\)\s*\.\s*extractall\s*\(/g;
const PY_TARFILE_EXTRACTALL_SHORT_RE = /\b(?:tf|tar|archive|t)\s*\.\s*extractall\s*\(/g;
const PY_TARFILE_FILTER_RE = /\bextractall\s*\([^)]*\bfilter\s*=\s*(?:["']data["']|tarfile\.data_filter)/;
const PY_TARFILE_IMPORT_RE = /\bimport\s+tarfile\b|\bfrom\s+tarfile\b/;
const PY_TARFILE_NAME_JOIN_RE = /\b(?:os\.path\.join|Path|os\.path\.normpath)\s*\([^)]*\b(?:member|m|entry|info)\s*\.\s*name\b/g;
const PY_ZIPFILE_EXTRACT_RE = /\b(?:zipfile\.[\w_]+\([^)]*\)|zf|zip_file|archive)\s*\.\s*extract(?:all)?\s*\(/g;
const PY_ZIPFILE_IMPORT_RE = /\bimport\s+zipfile\b|\bfrom\s+zipfile\b/;

const NODE_UNZIPPER_ENTRY_RE = /\bentry\s*\.\s*path\b[\s\S]{0,80}?\b(?:fs\.|path\.|createWriteStream|writeFile|pipe\s*\(\s*fs\.)/g;
const NODE_TAR_EXTRACT_RE = /\b(?:tar)\s*\.\s*(?:extract|x)\s*\(\s*\{[^}]*\bcwd\b/g;

import { blankComments } from './_comment-strip.js';

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanZipSlip(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  if (/\.(?:java|kt|kts|scala|groovy)$/i.test(fp)) {
    const code = blankComments(raw);
    // File-wide suppression: canonical path + startsWith pair present
    const hasCanonical = JAVA_SAFE_CANONICAL_RE.test(code) && JAVA_SAFE_STARTSWITH_RE.test(code);
    if (!hasCanonical) {
      const re = new RegExp(JAVA_NEW_FILE_WITH_ENTRY_RE.source, JAVA_NEW_FILE_WITH_ENTRY_RE.flags);
      let m;
      while ((m = re.exec(code))) {
        const line = _lineOf(raw, m.index);
        push({
          id: `zip-slip:${fp}:${line}:java`,
          file: fp, line,
          vuln: 'Zip Slip: ZipEntry.getName() joined into output path without normalization',
          severity: 'high',
          cwe: 'CWE-22',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'A zip entry name like `../../etc/passwd` lets an attacker write outside the extraction directory. Before any FileOutputStream / Files.write, canonicalize the joined path with `outFile.getCanonicalPath()` and verify `canonicalPath.startsWith(outDir.getCanonicalPath() + File.separator)`. Reject the entry on mismatch.',
          confidence: 0.85,
          parser: 'ZIP-SLIP',
        });
      }
    }
  }

  if (/\.py$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    const importsTarfile = PY_TARFILE_IMPORT_RE.test(code);
    const importsZipfile = PY_ZIPFILE_IMPORT_RE.test(code);
    // Per-call safe-shape check: extract the call's argument list and look for
    // filter="data" / filter=tarfile.data_filter in the same call. File-level
    // suppression was too aggressive — a safe function later in the file would
    // hide an unsafe one earlier.
    const _isFilteredExtract = (afterIdx) => {
      let depth = 0;
      let inS = null;
      for (let i = afterIdx; i < code.length && i < afterIdx + 500; i++) {
        const c = code[i];
        if (inS) {
          if (c === '\\') { i++; continue; }
          if (c === inS) inS = null;
          continue;
        }
        if (c === "'" || c === '"') { inS = c; continue; }
        if (c === '(') depth++;
        else if (c === ')') { depth--; if (depth === 0) {
          const args = code.substring(afterIdx, i);
          return /\bfilter\s*=\s*(?:["']data["']|tarfile\.data_filter)/.test(args);
        } }
      }
      return false;
    };
    if (importsTarfile) {
      const reA = new RegExp(PY_TARFILE_EXTRACTALL_RE.source, PY_TARFILE_EXTRACTALL_RE.flags);
      let m;
      while ((m = reA.exec(code))) {
        const openParen = m.index + m[0].length - 1; // position of '('
        if (_isFilteredExtract(openParen)) continue;
        const line = _lineOf(raw, m.index);
        push({
          id: `zip-slip:${fp}:${line}:py-tarfile`,
          file: fp, line,
          vuln: 'Zip Slip: tarfile.extractall() without filter="data" (CVE-2007-4559)',
          severity: 'high',
          cwe: 'CWE-22',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'Python 3.12+: pass `filter="data"` to extractall (or set TarFile.extraction_filter). For older Python: validate every member.name before extraction — reject paths containing `..`, absolute paths, or device files. The official guidance is in PEP 706.',
          confidence: 0.9,
          parser: 'ZIP-SLIP',
        });
      }
      const reB = new RegExp(PY_TARFILE_EXTRACTALL_SHORT_RE.source, PY_TARFILE_EXTRACTALL_SHORT_RE.flags);
      while ((m = reB.exec(code))) {
        const openParen = m.index + m[0].length - 1;
        if (_isFilteredExtract(openParen)) continue;
        const line = _lineOf(raw, m.index);
        push({
          id: `zip-slip:${fp}:${line}:py-tarfile-bare`,
          file: fp, line,
          vuln: 'Zip Slip: tar.extractall() without filter="data" (CVE-2007-4559)',
          severity: 'high',
          cwe: 'CWE-22',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'Python 3.12+: pass `filter="data"` to extractall. For older Python: validate every member.name (reject `..`, absolute paths, device files).',
          confidence: 0.85,
          parser: 'ZIP-SLIP',
        });
      }
    }
    if (importsTarfile) {
      const reC = new RegExp(PY_TARFILE_NAME_JOIN_RE.source, PY_TARFILE_NAME_JOIN_RE.flags);
      let m;
      while ((m = reC.exec(code))) {
        const line = _lineOf(raw, m.index);
        push({
          id: `zip-slip:${fp}:${line}:py-tarfile-join`,
          file: fp, line,
          vuln: 'Zip Slip: tar member.name joined into output path without validation',
          severity: 'high',
          cwe: 'CWE-22',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'Reject `member.name` if it contains `..`, starts with `/`, or is a device/symlink. Or migrate to extractall(filter="data").',
          confidence: 0.85,
          parser: 'ZIP-SLIP',
        });
      }
    }
    if (importsZipfile) {
      const re = new RegExp(PY_ZIPFILE_EXTRACT_RE.source, PY_ZIPFILE_EXTRACT_RE.flags);
      let m;
      while ((m = re.exec(code))) {
        const line = _lineOf(raw, m.index);
        push({
          id: `zip-slip:${fp}:${line}:py-zipfile`,
          file: fp, line,
          vuln: 'Zip Slip: zipfile.extract / extractall without path validation',
          severity: 'medium',
          cwe: 'CWE-22',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'Python\'s ZipFile.extract sanitizes some absolute paths but still resolves `..` segments in many CPython versions. Validate every name explicitly, or restrict the writable directory and verify the final path stays inside it.',
          confidence: 0.7,
          parser: 'ZIP-SLIP',
        });
      }
    }
  }

  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) {
    const code = blankComments(raw);
    const re = new RegExp(NODE_UNZIPPER_ENTRY_RE.source, NODE_UNZIPPER_ENTRY_RE.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = _lineOf(raw, m.index);
      push({
        id: `zip-slip:${fp}:${line}:node-entry`,
        file: fp, line,
        vuln: 'Zip Slip: archive entry.path written to filesystem without sanitization',
        severity: 'high',
        cwe: 'CWE-22',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Validate entry.path with `path.resolve(outDir, entry.path)` then assert `resolved.startsWith(outDir + path.sep)`. Reject entries where this is false.',
        confidence: 0.7,
        parser: 'ZIP-SLIP',
      });
    }
  }

  return findings;
}
