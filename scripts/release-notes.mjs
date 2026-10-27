#!/usr/bin/env node
// Prints the changelog section for one version, for use as a GitHub Release body.
//
//   node scripts/release-notes.mjs <version> [--changelog <path>]
//
// The root CHANGELOG.md is the only canonical source (scanner/CHANGELOG.md is a gitignored, generated copy). The section is printed
// exactly as written, minus its `## <version>` heading line; nothing is rewritten. Exits 1 when the version has no section, so a
// release workflow step cannot publish an empty Release page. The same extractor (changelogSection in release-check.mjs) backs the
// completion-declared release check. scripts/backfill-github-releases.mjs uses this module to create pages for older tags.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { changelogSection } from './release-check.mjs';

export const DEFAULT_CHANGELOG = fileURLToPath(new URL('../CHANGELOG.md', import.meta.url));

/** The section body without its heading line, or '' when the version has no section. */
export function releaseNotes(text, version) {
  const section = changelogSection(text, version);
  if (!section) return '';
  const nl = section.indexOf('\n');
  const body = nl === -1 ? '' : section.slice(nl + 1);
  // Drop leading blank lines without a nested-quantifier regex: the first line that has content starts the body.
  const lines = body.split('\n');
  const first = lines.findIndex((l) => l.trim() !== '');
  return first === -1 ? '' : lines.slice(first).join('\n').trimEnd();
}

function main(argv) {
  let version = null;
  let file = DEFAULT_CHANGELOG;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--changelog') file = path.resolve(argv[++i] || '');
    else if (!version) version = argv[i].replace(/^v/, '');
    else { process.stderr.write(`unexpected argument: ${argv[i]}\n`); return 2; }
  }
  if (!version) { process.stderr.write('usage: release-notes.mjs <version> [--changelog <path>]\n'); return 2; }
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { process.stderr.write(`cannot read ${file}: ${e.message}\n`); return 1; }
  const body = releaseNotes(text, version);
  if (!body) { process.stderr.write(`${file} has no non-empty section for ${version}\n`); return 1; }
  process.stdout.write(`${body}\n`);
  return 0;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exit(main(process.argv.slice(2)));
