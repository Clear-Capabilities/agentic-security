// Regenerates test/fixtures/portfolio/pre-change-pins.json. Run it ONLY against code that has not been changed for the feature:
// the pin is the output from before X-707 existed. Not a test file.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { rollupFleet, renderFleetSummary, renderFleetHtml } from '../../src/posture/fleet.js';
import { FLEET_RESULTS } from './fixtures-input.js';

const rollup = rollupFleet(FLEET_RESULTS);
const out = { synthetic: true, rollup, summary: renderFleetSummary(rollup), html: renderFleetHtml(rollup, FLEET_RESULTS) };
fs.writeFileSync(fileURLToPath(new URL('../fixtures/portfolio/pre-change-pins.json', import.meta.url)), `${JSON.stringify(out, null, 2)}\n`);
