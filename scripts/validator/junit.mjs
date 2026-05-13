#!/usr/bin/env node
// Emit a JUnit XML <testsuite> from one or more validator verdicts.
// Each verdict gets a <testcase>:
//   - TP_PROVEN / TP_CONFIRMED → failing testcase (with <failure>)
//   - PROBABLE_FP / INDETERMINATE → passing testcase
//   - REFUSED / INDETERMINATE_BY_CLASS → skipped testcase (<skipped/>)
//
// Usage: junit.js <verdicts.json>
//   where verdicts.json is an array of {id, file, line, vuln, verdict, reason}

import * as fs from 'node:fs';

function xmlEscape(s) {
  return String(s || '').replace(/[<>&"']/g, c => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;',
  }[c]));
}

function elapsed(v) {
  return (typeof v.durationMs === 'number') ? (v.durationMs / 1000).toFixed(3) : '0';
}

const file = process.argv[2];
if (!file) { console.error('Usage: junit.js <verdicts.json>'); process.exit(2); }
let verdicts;
try { verdicts = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { console.error('Cannot read verdicts:', e.message); process.exit(2); }
if (!Array.isArray(verdicts)) { console.error('Expected an array of verdicts.'); process.exit(2); }

const total = verdicts.length;
const failures = verdicts.filter(v => /^TP_/.test(v.verdict || '')).length;
const skipped = verdicts.filter(v => /^(REFUSED|INDETERMINATE_BY_CLASS)$/.test(v.verdict || '')).length;
const totalTime = verdicts.reduce((s, v) => s + (v.durationMs || 0), 0) / 1000;

let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
xml += `<testsuites name="agentic-security validate-findings" tests="${total}" failures="${failures}" skipped="${skipped}" time="${totalTime.toFixed(3)}">\n`;
xml += `  <testsuite name="security-findings" tests="${total}" failures="${failures}" skipped="${skipped}" time="${totalTime.toFixed(3)}">\n`;
for (const v of verdicts) {
  const name = xmlEscape(`${v.vuln || 'finding'} (${v.file || '?'}:${v.line || '?'})`);
  const classname = xmlEscape(v.id || 'security');
  const time = elapsed(v);
  xml += `    <testcase classname="${classname}" name="${name}" time="${time}">\n`;
  if (/^TP_/.test(v.verdict || '')) {
    xml += `      <failure message="${xmlEscape(v.verdict)}: ${xmlEscape(v.reason || '')}" type="${xmlEscape(v.cwe || 'security')}">\n`;
    xml += `${xmlEscape(v.detail || v.reason || '')}\n`;
    xml += `      </failure>\n`;
  } else if (/^(REFUSED|INDETERMINATE_BY_CLASS)$/.test(v.verdict || '')) {
    xml += `      <skipped message="${xmlEscape(v.verdict)}: ${xmlEscape(v.reason || '')}"/>\n`;
  } else {
    // PROBABLE_FP / INDETERMINATE → passing
    xml += `      <system-out>${xmlEscape(v.verdict + ': ' + (v.reason || ''))}</system-out>\n`;
  }
  xml += `    </testcase>\n`;
}
xml += `  </testsuite>\n</testsuites>\n`;
process.stdout.write(xml);
