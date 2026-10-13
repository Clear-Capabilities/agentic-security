import { test } from 'node:test';
import assert from 'node:assert/strict';
import { correlateImageVulnerabilities } from '../../src/artifact/vuln-correlate.js';

function inv(osPackages = [], appPackages = []) {
  return { osPackages, appPackages };
}

test('VC/1: components passed to queryOSVFn are the union of OS and app packages', async () => {
  let seenComponents = null;
  const fake = async (components) => { seenComponents = components; return []; };
  await correlateImageVulnerabilities({
    inventory: inv([{ name: 'curl', ecosystem: 'Debian' }], [{ name: 'lodash', ecosystem: 'npm' }]),
    fileContents: {},
    queryOSVFn: fake,
  });
  assert.equal(seenComponents.length, 2);
  assert.ok(seenComponents.some((c) => c.name === 'curl'));
  assert.ok(seenComponents.some((c) => c.name === 'lodash'));
});

test('VC/2: fileContents is forwarded to queryOSVFn (unpinned-dep detection needs it)', async () => {
  let seenFc = null;
  const fake = async (_c, fc) => { seenFc = fc; return []; };
  await correlateImageVulnerabilities({ inventory: inv(), fileContents: { 'a.txt': 'x' }, queryOSVFn: fake });
  assert.deepEqual(seenFc, { 'a.txt': 'x' });
});

test('VC/3: the vulnerability results from queryOSVFn are returned unmodified', async () => {
  const fake = async () => [{ type: 'osv', id: 'GHSA-xxxx' }];
  const { vulnerabilities } = await correlateImageVulnerabilities({ inventory: inv(), fileContents: {}, queryOSVFn: fake });
  assert.deepEqual(vulnerabilities, [{ type: 'osv', id: 'GHSA-xxxx' }]);
});

test('VC/4: requires a queryOSVFn function', async () => {
  await assert.rejects(correlateImageVulnerabilities({ inventory: inv(), fileContents: {}, queryOSVFn: null }), TypeError);
});

test('VC/5: requires an inventory with array osPackages/appPackages', async () => {
  await assert.rejects(correlateImageVulnerabilities({ inventory: {}, fileContents: {}, queryOSVFn: async () => [] }), TypeError);
});
