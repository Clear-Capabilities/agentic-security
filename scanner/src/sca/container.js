// 0.9.0 Feat-14: Container base image EOL detection — maps FROM lines to known-vulnerable distro versions.
//
// Two passes:
//   1. Parse `FROM <image>:<tag>` lines and check the tag against a vendored
//      base-images map (alpine/debian/ubuntu/node/python). Emit a finding for
//      EOL or floating tags.
//   2. Parse `RUN apt-get install` / `apk add` package lists and synthesize
//      lightweight components[] entries that the SCA OSV pipeline can query.
//
// All-local: no Docker registry pulls, no shell-out to docker. Just regex.

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _BASE_IMAGES = (() => {
  try {
    const raw = _require('./base-images.json');
    const out = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue;
      out[k] = v;
    }
    return out;
  } catch (_) {
    return null;
  }
})();

const _DOCKERFILE_RE = /(?:^|\/)(?:[Dd]ockerfile|[^/]+\.dockerfile)$/i;

// FROM <image>[:<tag>] [AS <stage>]
const _FROM_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+?)(?::([\w.\-]+))?(?:@sha256:[a-f0-9]{64})?(?:\s+AS\s+\S+)?\s*$/im;

// FROM <image>:<tag> covering all FROM lines in the file
// The digest is CAPTURED, not merely tolerated. Discarding it made
// `FROM ubuntu@sha256:…` parse as image=ubuntu with no tag, which `_scoreTag`
// then treats as `latest` — so the most tightly pinned form a Dockerfile can
// use was reported as "ubuntu:latest (floating tag)". A false positive on the
// hardened configuration is worse than a miss: it tells the people who did the
// right thing that they did the wrong one.
//
// Found by bench/iac-coverage, whose verdict-flip scoring exists precisely to
// catch a rule that fires on both variants of a control.
const _ALL_FROM_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+?)(?::([\w.\-]+))?(?:@sha256:([a-f0-9]{64}))?(?:\s+AS\s+\S+)?\s*$/img;

// `apt-get install -y pkg pkg pkg` / `apk add pkg pkg`
const _APT_INSTALL_RE = /\bapt(?:-get)?\s+install\b[^\n]*?(?:--?[\w-]+\s+)*((?:[a-z0-9][\w.+-]*(?:=[\w.+:-]+)?\s*)+)/gi;
const _APK_ADD_RE     = /\bapk\s+(?:--no-cache\s+)?(?:--update\s+)?add\b[^\n]*?(?:--?[\w-]+\s+)*((?:[a-z0-9][\w.+-]*(?:=[\w.+:-]+)?\s*)+)/gi;

function _scoreTag(image, tag) {
  if (!_BASE_IMAGES) return null;
  const m = _BASE_IMAGES[image];
  if (!m) return null;
  // Direct tag match
  if (m[tag]) return { ...m[tag], image, tag };
  // Major-only match: tag '20.04-slim' falls back to '20.04'
  for (const k of Object.keys(m)) {
    if (tag && tag.startsWith(k + '.')) return { ...m[k], image, tag };
    if (tag && tag.startsWith(k + '-')) return { ...m[k], image, tag };
    if (tag === k) return { ...m[k], image, tag };
  }
  // Tag missing entirely (e.g. "FROM alpine") → treat as 'latest'
  if (!tag && m.latest) return { ...m.latest, image, tag: 'latest' };
  return null;
}

export function scanContainer(fp, raw) {
  if (!_DOCKERFILE_RE.test(fp.replace(/\\/g, '/'))) return [];
  if (!raw || raw.length > 200_000) return [];
  const findings = [];
  const lines = raw.split('\n');
  let m;

  // Pass 1: FROM lines
  _ALL_FROM_RE.lastIndex = 0;
  while ((m = _ALL_FROM_RE.exec(raw))) {
    const image = m[1].split('/').pop(); // strip registry / namespace prefixes
    const tag = m[2] || '';
    const digest = m[3] || '';
    const line = raw.substring(0, m.index).split('\n').length;
    // Digest-pinned with no tag: there is nothing to score. The reference is
    // immutable, which is the recommended form, and inventing a `latest` tag
    // for it produces the exact opposite advice.
    if (digest && !tag) continue;
    const score = _scoreTag(image, tag);
    if (!score) continue;
    // `image:22.04@sha256:…` — the tag can still be end-of-life, and that is
    // worth saying, but it is not a FLOATING tag: the digest pins it.
    if (digest && !score.eol) continue;
    findings.push({
      id: `container-base:${fp}:${line}:${image}:${tag || 'latest'}`,
      kind: 'container', severity: score.sev,
      vuln: `Container base image: ${image}:${tag || 'latest'} ${score.eol ? '(EOL)' : '(floating tag)'}`,
      cwe: score.eol ? 'CWE-1104' : 'CWE-1357',
      stride: 'Tampering',
      file: fp, line, snippet: (lines[line - 1] || '').trim(),
      fix: score.message,
    });
  }

  return findings;
}

function _parsePackagesFromDockerfile(raw) {
  // Pass 2: apt/apk packages — surface as components hint for the SCA pipeline.
  // We do NOT query OSV here (the engine's SCA pass owns that). Just collect names.
  const packages = [];
  let m;
  _APT_INSTALL_RE.lastIndex = 0;
  while ((m = _APT_INSTALL_RE.exec(raw))) {
    for (const tok of m[1].split(/\s+/)) {
      const t = tok.trim();
      if (!t || t.startsWith('-')) continue;
      const [name, ver] = t.split('=', 2);
      if (/^[a-z0-9][\w.+-]*$/.test(name)) packages.push({ ecosystem: 'debian', name, version: ver || '' });
    }
  }
  _APK_ADD_RE.lastIndex = 0;
  while ((m = _APK_ADD_RE.exec(raw))) {
    for (const tok of m[1].split(/\s+/)) {
      const t = tok.trim();
      if (!t || t.startsWith('-')) continue;
      const [name, ver] = t.split('=', 2);
      if (/^[a-z0-9][\w.+-]*$/.test(name)) packages.push({ ecosystem: 'alpine', name, version: ver || '' });
    }
  }
  return packages;
}

// Extract Dockerfile-declared apt/apk packages across every Dockerfile in
// fileContents, as full SCA component entries — mirrors image-packages.js's
// extractImagePackages(fileContents) signature/shape so both plug into the
// engine's components merge the same way. Deliberately independent of
// scanContainer's return value: piggybacking package data on a *finding*
// meant no packages were ever surfaced for a Dockerfile whose FROM line
// wasn't itself flagged (the common case — most Dockerfiles pin a
// non-EOL base image), even though apt/apk lines were still present and
// parseable.
export function extractContainerPackages(fileContents) {
  const comps = [];
  const seen = new Set();
  for (const [file, content] of Object.entries(fileContents || {})) {
    if (!_DOCKERFILE_RE.test(file.replace(/\\/g, '/'))) continue;
    if (!content || content.length > 200_000) continue;
    for (const p of _parsePackagesFromDockerfile(content)) {
      const key = `${p.ecosystem}:${p.name}:${p.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      comps.push({
        name: p.name, version: p.version, group: '', scope: 'required',
        purl: `pkg:${p.ecosystem === 'debian' ? 'deb/debian' : 'apk/alpine'}/${encodeURIComponent(p.name)}${p.version ? '@' + encodeURIComponent(p.version) : ''}`,
        ecosystem: p.ecosystem, filePath: file, isUnpinned: !p.version, isOsPackage: true, reachable: true,
      });
    }
  }
  return comps;
}
