import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifests } from '../../src/engine.js';

test('package.json dependencies get a line number', () => {
  const text = [
    '{',
    '  "name": "x",',
    '  "dependencies": {',
    '    "left-pad": "^1.0.0",',
    '    "lodash": "^4.17.21"',
    '  },',
    '  "devDependencies": {',
    '    "mocha": "^10.0.0"',
    '  }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const leftPad = deps.find((d) => d.name === 'left-pad');
  const mocha = deps.find((d) => d.name === 'mocha');
  assert.equal(leftPad.line, 4);
  assert.equal(mocha.line, 8);
});

test('requirements.txt dependencies get a line number, comments/blank lines skipped', () => {
  const text = [
    '# comment',
    '',
    'flask==2.0.0',
    'requests>=2.28.0',
  ].join('\n');
  const deps = parseManifests({ 'requirements.txt': text });
  const flask = deps.find((d) => d.name === 'flask');
  const requests = deps.find((d) => d.name === 'requests');
  assert.equal(flask.line, 3);
  assert.equal(requests.line, 4);
});

test('package.json compact single-line section resolves the correct line', () => {
  const text = [
    '{',
    '  "dependencies": { "left-pad": "1.0.0" }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const leftPad = deps.find((d) => d.name === 'left-pad');
  assert.equal(leftPad.line, 2);
});

test('package.json same dep name in both dependencies and devDependencies resolves each occurrence independently', () => {
  const text = [
    '{',
    '  "dependencies": { "lodash": "1.0.0" },',
    '  "devDependencies": {',
    '    "lodash": "^4.17.21"',
    '  }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const required = deps.find((d) => d.name === 'lodash' && d.scope === 'required');
  const optional = deps.find((d) => d.name === 'lodash' && d.scope === 'optional');
  assert.equal(required.line, 2);
  assert.equal(optional.line, 4);
});

test('package.json scoped package name gets the correct line', () => {
  const text = [
    '{',
    '  "dependencies": {',
    '    "@org/pkg": "1.0.0"',
    '  }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const scoped = deps.find((d) => d.name === '@org/pkg');
  assert.equal(scoped.line, 3);
});

test('package.json dependency name with a regex-special character (dot) gets the correct line', () => {
  const text = [
    '{',
    '  "dependencies": {',
    '    "lodash.merge": "1.0.0"',
    '  }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const dotted = deps.find((d) => d.name === 'lodash.merge');
  assert.equal(dotted.line, 3);
});
