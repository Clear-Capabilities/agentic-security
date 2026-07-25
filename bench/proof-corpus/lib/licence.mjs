// Licence detection for proof-corpus targets.
//
// Detects an SPDX identifier from a repository's licence file, falling back to
// a package manifest's declared field. Text matching is deliberately anchored
// on the distinctive title lines rather than full-text comparison: we need the
// licence *family* for the scorecard, not a legal determination.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Order matters: AGPL must be tested before GPL because its title contains
// "GENERAL PUBLIC LICENSE" as a substring.
const PATTERNS = [
  { spdx: 'AGPL-3.0', re: /GNU AFFERO GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'LGPL-3.0', re: /GNU LESSER GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'LGPL-2.1', re: /GNU LESSER GENERAL PUBLIC LICENSE\s*\n?\s*Version 2\.1/i },
  { spdx: 'GPL-3.0', re: /GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 3/i },
  { spdx: 'GPL-2.0', re: /GNU GENERAL PUBLIC LICENSE\s*\n?\s*Version 2/i },
  { spdx: 'Apache-2.0', re: /Apache License\s*\n?\s*Version 2\.0/i },
  { spdx: 'BUSL-1.1', re: /Business Source License 1\.1/i },
  { spdx: 'FSL-1.1', re: /Functional Source License,?\s*Version 1\.1/i },
  { spdx: 'MPL-2.0', re: /Mozilla Public License Version 2\.0/i },
  { spdx: 'BSD-3-Clause', re: /Redistribution and use in source and binary forms[\s\S]{0,2000}?Neither the name of/i },
  { spdx: 'BSD-2-Clause', re: /Redistribution and use in source and binary forms/i },
  { spdx: 'ISC', re: /ISC License/i },
  { spdx: 'MIT', re: /MIT License|Permission is hereby granted, free of charge/i },
];

const LICENCE_FILES = [
  'LICENSE', 'LICENSE.md', 'LICENSE.txt',
  'LICENCE', 'LICENCE.md', 'LICENCE.txt',
  'COPYING', 'COPYING.txt',
];

export function detectLicenceText(text) {
  if (typeof text !== 'string' || !text) return null;
  // Only the head matters — the title block is at the top, and full-file
  // regex over a long licence is wasteful.
  const head = text.slice(0, 8000);
  for (const { spdx, re } of PATTERNS) {
    if (re.test(head)) return spdx;
  }
  return null;
}

export function detectLicence(repoDir) {
  const none = { spdx: null, source: 'none', file: null };
  if (typeof repoDir !== 'string') return none;

  for (const name of LICENCE_FILES) {
    let text;
    try {
      text = fs.readFileSync(path.join(repoDir, name), 'utf8');
    } catch { continue; }
    const spdx = detectLicenceText(text);
    if (spdx) return { spdx, source: 'file', file: name };
  }

  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(repoDir, 'package.json'), 'utf8'));
    const lic = typeof pkg.license === 'string' ? pkg.license : null;
    if (lic) return { spdx: lic, source: 'package-json', file: 'package.json' };
  } catch { /* absent or malformed — fall through */ }

  return none;
}
