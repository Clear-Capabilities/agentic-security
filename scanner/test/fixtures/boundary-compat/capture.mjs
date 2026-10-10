// Recapture the previous-schema fixture for the boundary presentation work (X-307.AC01).
//   node capture.mjs [path-to-a-scanner-directory]
// Prints one JSON document with what the JSON report and the Markdown report emit for the compat input. It was captured from
// the sources of commit e28a262c, before boundary fields were wired into those surfaces. The compatibility test requires the
// current code to keep every one of these values and, with the feature off, to add nothing.
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { META, scanInput } from '../verification-compat/inputs.mjs';

const scanner = path.resolve(process.argv[2] || '.');
const { toJSON, normalizeFindings, toMarkdown } = await import(pathToFileURL(path.join(scanner, 'src', 'report', 'index.js')).href);
const report = toJSON(scanInput(), META);
console.log(JSON.stringify({
  capturedFrom: 'commit e28a262c scanner/src',
  reportJson: { topLevelKeys: Object.keys(report).sort(), finding: normalizeFindings(scanInput())[0] },
  markdown: toMarkdown(scanInput(), META),
}, null, 2));
