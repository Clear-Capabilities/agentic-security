#!/usr/bin/env node
// Creates GitHub Release pages for tags that already exist, from their changelog sections.
//
//   node scripts/backfill-github-releases.mjs v0.185.0 v0.186.0 ...            # dry run (the default): prints, changes nothing
//   node scripts/backfill-github-releases.mjs --apply v0.185.0 v0.186.0 ...    # creates the missing Releases
//
// Safety: it never creates, moves or deletes a tag. `gh release create --verify-tag` fails when the tag is absent instead of
// minting one from the default branch. A tag that already has a Release is skipped (never edited), and a tag with no changelog
// section is reported and skipped. The body is the root CHANGELOG.md section, via scripts/release-notes.mjs.
import * as fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { DEFAULT_CHANGELOG, releaseNotes } from './release-notes.mjs';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const tags = args.filter((a) => !a.startsWith('--'));
if (!tags.length) { process.stderr.write('usage: backfill-github-releases.mjs [--apply] <tag>...   (dry run unless --apply)\n'); process.exit(2); }

const changelog = fs.readFileSync(DEFAULT_CHANGELOG, 'utf8');
const gh = (a, input) => spawnSync('gh', a, { encoding: 'utf8', input });
let failed = 0;
process.stdout.write(apply ? 'APPLY: creating missing Releases\n' : 'DRY RUN: nothing will be created (pass --apply to create)\n');
for (const tag of tags) {
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) { process.stdout.write(`${tag}: skipped, not a vX.Y.Z tag\n`); failed++; continue; }
  const body = releaseNotes(changelog, tag.slice(1));
  if (!body) { process.stdout.write(`${tag}: skipped, no changelog section\n`); failed++; continue; }
  const cmd = ['release', 'create', tag, '--verify-tag', '--title', tag, '--notes-file', '-'];
  if (!apply) { process.stdout.write(`${tag}: would run gh ${cmd.join(' ')} (${body.length} chars of notes), unless a Release already exists\n`); continue; }
  const exists = gh(['release', 'view', tag]);
  if (exists.status === 0) { process.stdout.write(`${tag}: Release already exists, left alone\n`); continue; }
  const r = gh(cmd, body);
  if (r.status === 0) process.stdout.write(`${tag}: created\n`);
  else { process.stdout.write(`${tag}: FAILED ${String(r.stderr).trim()}\n`); failed++; }
}
process.exit(failed ? 1 : 0);
