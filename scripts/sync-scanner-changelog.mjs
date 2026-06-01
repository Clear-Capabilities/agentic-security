#!/usr/bin/env node
// prepublish: regenerate the (gitignored) scanner/CHANGELOG.md from the canonical
// root CHANGELOG.md, and refuse to publish a version that has no changelog entry.
//
// Why this exists: scanner/CHANGELOG.md is gitignored and regenerated on every
// publish, so the previous "scanner copy differs from root" guard tripped on
// every release for a difference that never mattered (the copy was simply stale
// from the prior publish). The check that *does* matter is "the version being
// published is documented" — that's the guard here; the copy is then always
// overwritten (self-healing), so a stale generated file can never block a publish.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const rootChangelog = join(repoRoot, 'CHANGELOG.md');
const scannerChangelog = join(repoRoot, 'scanner', 'CHANGELOG.md');
const scannerPkg = join(repoRoot, 'scanner', 'package.json');

if (!existsSync(rootChangelog)) {
  console.error(`prepublish: root CHANGELOG.md not found at ${rootChangelog}.`);
  process.exit(1);
}

const version = JSON.parse(readFileSync(scannerPkg, 'utf8')).version;
const src = readFileSync(rootChangelog, 'utf8');

// The one guard worth keeping: a "## <version>" heading must exist for what we ship.
const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const versionHeading = new RegExp(`^##\\s+${escaped}(?:\\s|$)`, 'm');
if (!versionHeading.test(src)) {
  console.error(`prepublish: ../CHANGELOG.md has no "## ${version}" entry.`);
  console.error(`Add a "## ${version} — <summary>" section to the root CHANGELOG before publishing.`);
  process.exit(1);
}

// Self-healing: always regenerate the generated copy from root. No stale-diff trips.
writeFileSync(scannerChangelog, src);
console.log(`prepublish: scanner/CHANGELOG.md synced from root (## ${version} present).`);
