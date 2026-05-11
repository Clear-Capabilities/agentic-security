#!/usr/bin/env node
// One-shot CLI tool. Sync I/O is correct here — the process exits immediately
// after the work is done, so there's no event loop to block.
'use strict';
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const target = argv[0] || './report.json';

const data = JSON.parse(fs.readFileSync(target, 'utf8'));   // sync I/O — fine in CLI
const summary = `Findings: ${data.findings?.length || 0}`;
fs.writeFileSync('summary.txt', summary);                    // sync I/O — fine in CLI

if (!fs.existsSync('./output')) {                            // sync I/O — fine in CLI
  fs.mkdirSync('./output');
}

console.log('done');
process.exit(0);
