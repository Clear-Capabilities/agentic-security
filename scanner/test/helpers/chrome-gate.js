// Chrome rendering tests are QUARANTINED from the combined `npm test` run.
//
// They launch a real headless Chrome and wait on a screenshot or print, so their duration depends on the machine's load and on Chrome's
// own state far more than on this code: in the combined run (thousands of tests in parallel) they hit their deadline intermittently,
// failed the pre-push gate for reasons that had nothing to do with the push, and trained people to bypass the gate. A gate that cries
// wolf is not a gate.
//
// They still run, deadlines unchanged, as their own script and CI job: `npm run test:chrome` (sets AGENTIC_SECURITY_CHROME_TESTS=1).
// Without that variable, or without a usable Chrome, the same tests are reported as SKIPPED, with this reason visible in the name list.
import { test } from 'node:test';
import { probeChromeAvailable } from '../../src/ir/chrome-probe.mjs';

export const chrome = probeChromeAvailable();
export const chromeTestsEnabled = chrome.ok && process.env.AGENTIC_SECURITY_CHROME_TESTS === '1';
export const itChrome = chromeTestsEnabled ? test : test.skip;
