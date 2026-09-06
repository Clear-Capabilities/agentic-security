// Threat-model auto-derivation (FR-LOGIC-10) had NO test coverage at all
// before this file — which is exactly how three lexical-inference false
// positives shipped undetected (a real customer report). All three share one
// root cause: a heuristic keyed on an identifier/text SUBSTRING with no check
// that the surrounding code actually does what the category name claims.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAssetInventory, buildTrustBoundaries } from '../src/posture/threat-model.js';

test('asset inventory: requests.Session() is an HTTP client, not an authenticated user session', () => {
  const fc = { 'client.py': 'class Fetcher:\n    def __init__(self):\n        self.session = requests.Session()\n' };
  const assets = buildAssetInventory(fc);
  const sessions = assets.filter(a => a.category === 'session');
  assert.deepEqual(sessions, [], `requests.Session() must not be classified as a user session: ${JSON.stringify(sessions)}`);
});

test('asset inventory: aiohttp.ClientSession() and httpx.Client() are also HTTP clients, not user sessions', () => {
  const fc = {
    'a.py': 'self.session = aiohttp.ClientSession()',
    'b.py': 'self.session=httpx.Client()',
  };
  const assets = buildAssetInventory(fc);
  assert.deepEqual(assets.filter(a => a.category === 'session'), []);
});

test('asset inventory: a real user session assignment is still reported', () => {
  const fc = { 'auth.py': 'req.session = load_user_session(user_id)\ntoken = generate_jwt(user)\n' };
  const assets = buildAssetInventory(fc);
  const sessions = assets.filter(a => a.category === 'session');
  assert.equal(sessions.length, 2, 'a real session load and a real JWT issuance must both still be reported');
});

test('trust boundaries: publisher_domain / published_at are not a queue producer', () => {
  // Root cause: `(?:kafka|pubsub|sqs|sns)\.produce|\.publish|\.sendMessage`
  // parses as three TOP-LEVEL alternatives — only the first is scoped to a
  // queue library. `.publish` alone matches the first 8 characters of
  // "publisher"/"published", with no queue library and no method call at all.
  const fc = {
    'bundle.py': 'bundle.publisher_domain = extract_domain(url)\nbundle.published_at = now()\n',
  };
  const boundaries = buildTrustBoundaries(fc);
  const producers = boundaries.filter(b => b.type === 'queue-producer');
  assert.deepEqual(producers, [], `plain field assignment is not a queue boundary: ${JSON.stringify(producers)}`);
});

test('trust boundaries: rxjs-style .subscribe() is not a queue consumer', () => {
  const fc = { 'ui.js': 'observable.subscribe(callback);\n' };
  const boundaries = buildTrustBoundaries(fc);
  assert.deepEqual(boundaries.filter(b => b.type === 'queue-consumer'), []);
});

test('trust boundaries: a real kafka/sqs/sns producer and consumer are still reported', () => {
  const fc = {
    'producer.js': 'kafka.publish(topic, message);\n',
    'consumer.js': 'sqs.receiveMessage(params);\n',
  };
  const boundaries = buildTrustBoundaries(fc);
  assert.ok(boundaries.some(b => b.type === 'queue-producer'), 'a real kafka.publish( call must still be reported');
  assert.ok(boundaries.some(b => b.type === 'queue-consumer'), 'a real sqs.receiveMessage( call must still be reported');
});
