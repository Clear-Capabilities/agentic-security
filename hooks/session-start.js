#!/usr/bin/env node
// SessionStart hook: print a one-line tip if no baseline exists yet.
// Plain CommonJS — no imports, no warnings.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const blPath = path.join(cwd, '.agentic-security', 'baseline.json');
if (!fs.existsSync(blPath)) {
  console.log('agentic-security: no baseline. Run /agentic-security:security-scan then /agentic-security:security-baseline save to enable commit gating.');
}
process.exit(0);
