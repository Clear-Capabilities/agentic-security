// observation-store.test.js — Task 4 of the M5 "Runtime-Corroborated
// Digital Twin" (7b) sub-project. `observation-store.js` is the impure
// layer: a directory of independently-readable, immutable whole files,
// one per adapter import.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  OBSERVATION_STORE_DIR, OBSERVATION_IMPORT_VERSION,
  observationsDir, importFileName, validateObservationImport,
  persistObservationImport, loadObservationImports, loadObservationImport,
  loadObservations, deleteObservationImport,
} from '../../src/lineage/observation-store.js';
import { statePath, isSafeStateDir, stateWritesEnabled, setStateWritesEnabled } from '../../src/posture/state-dir.js';
import {
  ENCRYPTION_POLICY_FILE, isEncryptedEnvelope, maybeDecryptForRead,
} from '../../src/posture/encryption-provider.js';
import { observationImportId, observationId } from '../../src/lineage/ids.js';
import { RUNTIME_OBSERVATION_VERSION } from '../../src/lineage/runtime-observation.js';
import { matchObservationToGraph } from '../../src/lineage/observation-correlation.js';
import { parseNativeJsonlObservations } from '../../src/lineage/observation-adapters.js';
import { signLastScan } from '../../src/posture/integrity.js';

const MODULE_PATH = fileURLToPath(new URL('../../src/lineage/observation-store.js', import.meta.url));
const FIXTURES_DIR = fileURLToPath(new URL('../fixtures/runtime-observations/', import.meta.url));

// ── Test helpers ─────────────────────────────────────────────────────────

function makeTempProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-obs-store-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp"}\n');
  return root;
}

function withIsolatedXdgHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-store-xdg-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  try { return fn(home); }
  finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const EMPTY_GRAPH = { nodes: [], edges: [], flows: [] };

function baseObservation(overrides = {}) {
  const draft = {
    version: RUNTIME_OBSERVATION_VERSION,
    adapter: 'native-jsonl',
    source: 'native.jsonl:test-fixture',
    environment: 'production',
    windowStart: '2026-07-01T00:00:00.000Z',
    windowEnd: '2026-08-31T00:00:00.000Z',
    importedAt: '2026-08-31T12:00:00.000Z',
    retention: { expiresAt: null },
    attributes: { 'destination.host': 'api.stripe.com' },
    eventCountBand: '101-1k',
    firstObservedAt: '2026-08-02T10:00:00.000Z',
    lastObservedAt: '2026-08-30T10:00:00.000Z',
    ...overrides,
  };
  return {
    ...draft,
    id: observationId(draft, [JSON.stringify(draft.attributes)]),
    ...matchObservationToGraph(EMPTY_GRAPH, draft),
  };
}

function draftsToObservations(drafts) {
  return drafts.map((draft) => ({
    ...draft,
    id: observationId(draft, [JSON.stringify(draft.attributes)]),
    ...matchObservationToGraph(EMPTY_GRAPH, draft),
  }));
}

function baseImport(overrides = {}) {
  const observations = overrides.observations ?? [baseObservation()];
  const base = {
    version: OBSERVATION_IMPORT_VERSION,
    adapter: 'native-jsonl',
    source: 'native.jsonl:test-fixture',
    environment: 'production',
    windowStart: '2026-07-01T00:00:00.000Z',
    windowEnd: '2026-08-31T00:00:00.000Z',
    importedAt: overrides.importedAt ?? '2026-08-31T12:00:00.000Z',
    retention: { expiresAt: null },
    ...overrides,
    observations,
  };
  if (!('id' in overrides)) {
    base.id = observationImportId(base);
  }
  return base;
}

function fixtureContext(overrides = {}) {
  return {
    version: RUNTIME_OBSERVATION_VERSION,
    adapter: 'native-jsonl',
    source: 'native.jsonl:test-fixture',
    environment: 'production',
    windowStart: '2026-07-01T00:00:00.000Z',
    windowEnd: '2026-08-31T00:00:00.000Z',
    importedAt: '2026-08-31T12:00:00.000Z',
    retention: { expiresAt: null },
    ...overrides,
  };
}

// =====================================================================
// OS/1 — observationsDir + the registry-guard shape.
// =====================================================================

test('OS/1a: observationsDir resolves to <root>/.agentic-security/runtime-observations, via statePath', () => {
  const root = makeTempProject();
  try {
    assert.equal(observationsDir(root), statePath(root, 'runtime-observations'));
    assert.equal(observationsDir(root), path.join(root, '.agentic-security', 'runtime-observations'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/1b: the registry-guard shape — a real quoted statePath(scanRoot, \'runtime-observations\') literal, and OBSERVATION_STORE_DIR is never statePath\'s second argument', () => {
  const src = fs.readFileSync(MODULE_PATH, 'utf8');
  assert.ok(
    src.includes("statePath(scanRoot, 'runtime-observations')"),
    'observation-store.js must call statePath with the literal string \'runtime-observations\' — the completeness guard (artifact-registry-completeness.test.js) needs a quoted literal to see the call site at all, exactly the bypass that let runtime-trace.jsonl (and graph-snapshot.js:36) go unregistered',
  );
  // Every statePath( call site in the source: none may pass OBSERVATION_STORE_DIR
  // as the literal second argument.
  const statePathCalls = [...src.matchAll(/statePath\(([^)]*)\)/g)].map((m) => m[1]);
  assert.ok(statePathCalls.length > 0, 'expected at least one statePath( call site');
  for (const args of statePathCalls) {
    assert.ok(
      !/,\s*OBSERVATION_STORE_DIR\b/.test(args),
      `statePath must never be called with OBSERVATION_STORE_DIR as an argument (found: statePath(${args}))`,
    );
  }
});

// =====================================================================
// OS/2 — missing-directory tolerance.
// =====================================================================

test('OS/2a: loadObservationImports/loadObservations on a missing directory return [], never throw; loadObservationImport returns null', () => {
  const root = makeTempProject();
  try {
    assert.deepEqual(loadObservationImports(root), []);
    assert.deepEqual(loadObservations(root), []);
    assert.equal(loadObservationImport(root, 'obsimport:0123456789ab'), null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/3 — round trip, union, ordering.
// =====================================================================

test('OS/3a: round trip — persist one import with two observations, load it back deep-equal, and loadObservations returns both sorted by id', () => {
  const root = makeTempProject();
  try {
    const obsA = baseObservation({ attributes: { 'destination.host': 'api.stripe.com' } });
    const obsB = baseObservation({ attributes: { 'destination.host': 'api.anthropic.com' } });
    assert.notEqual(obsA.id, obsB.id, 'the two observations must have distinct ids for this test to be meaningful');
    const record = baseImport({ observations: [obsA, obsB] });

    const result = persistObservationImport(root, record);
    assert.equal(result.ok, true, `expected a successful persist: ${JSON.stringify(result)}`);
    assert.ok(fs.existsSync(result.path));

    const imports = loadObservationImports(root);
    assert.equal(imports.length, 1);
    assert.deepEqual(imports[0], record);

    const observations = loadObservations(root);
    assert.equal(observations.length, 2);
    const expectedIds = [obsA.id, obsB.id].sort();
    assert.deepEqual(observations.map((o) => o.id), expectedIds);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/3b: two imports are two files, both readable, and loadObservations unions them deduplicated by observation id', () => {
  const root = makeTempProject();
  try {
    const shared = baseObservation({ attributes: { 'destination.host': 'shared.example.com' } });
    const onlyInFirst = baseObservation({ attributes: { 'destination.host': 'first-only.example.com' } });
    const onlyInSecond = baseObservation({ attributes: { 'destination.host': 'second-only.example.com' } });

    const first = baseImport({ importedAt: '2026-08-31T12:00:00.000Z', observations: [shared, onlyInFirst] });
    const second = baseImport({ importedAt: '2026-08-31T13:00:00.000Z', observations: [shared, onlyInSecond] });
    assert.notEqual(first.id, second.id, 'distinct importedAt must yield distinct import ids');

    const r1 = persistObservationImport(root, first);
    const r2 = persistObservationImport(root, second);
    assert.equal(r1.ok, true, JSON.stringify(r1));
    assert.equal(r2.ok, true, JSON.stringify(r2));
    assert.notEqual(r1.path, r2.path, 'two imports must be two distinct files');

    const files = fs.readdirSync(observationsDir(root)).filter((f) => f.endsWith('.json'));
    assert.equal(files.length, 2);

    const imports = loadObservationImports(root);
    assert.equal(imports.length, 2);

    const observations = loadObservations(root);
    const ids = observations.map((o) => o.id);
    assert.equal(ids.length, new Set(ids).size, 'no duplicate ids in the flattened, deduplicated list');
    assert.ok(ids.includes(shared.id), 'the shared observation id must appear exactly once');
    assert.equal(ids.filter((id) => id === shared.id).length, 1);
    assert.ok(ids.includes(onlyInFirst.id));
    assert.ok(ids.includes(onlyInSecond.id));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/3c: loadObservationImports is newest-first by mtime', () => {
  const root = makeTempProject();
  try {
    const older = baseImport({ importedAt: '2026-08-31T09:00:00.000Z' });
    const newer = baseImport({ importedAt: '2026-08-31T10:00:00.000Z' });
    assert.notEqual(older.id, newer.id);

    const r1 = persistObservationImport(root, older);
    const r2 = persistObservationImport(root, newer);
    assert.equal(r1.ok, true, JSON.stringify(r1));
    assert.equal(r2.ok, true, JSON.stringify(r2));

    // Touch the second file's mtime forward so ordering is unambiguous
    // regardless of filesystem timestamp resolution.
    const future = new Date(Date.now() + 60_000);
    fs.utimesSync(r2.path, future, future);
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(r1.path, past, past);

    const imports = loadObservationImports(root);
    assert.equal(imports.length, 2);
    assert.equal(imports[0].id, newer.id, 'the most-recently-touched file must come first');
    assert.equal(imports[1].id, older.id);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/4 — immutability + retention.
// =====================================================================

test('OS/4a: deleteObservationImport removes exactly one file, leaves every sibling intact, and returns true; a second call returns false', () => {
  const root = makeTempProject();
  try {
    const first = baseImport({ importedAt: '2026-08-31T09:00:00.000Z' });
    const second = baseImport({ importedAt: '2026-08-31T10:00:00.000Z' });
    const r1 = persistObservationImport(root, first);
    const r2 = persistObservationImport(root, second);
    assert.equal(r1.ok, true, JSON.stringify(r1));
    assert.equal(r2.ok, true, JSON.stringify(r2));

    const deleted = deleteObservationImport(root, first.id);
    assert.equal(deleted, true,
      'FR-505: "Observation stores follow artifact encryption, retention, reset, access-control, and no-egress rules" requires real per-import deletion — this is the property an append-only hash chain (remediation-ledger.js\'s own shape) could not provide, since unlinking the middle of a hash chain breaks every entry after it');
    assert.ok(!fs.existsSync(r1.path), 'the deleted import\'s own file must be gone');
    assert.ok(fs.existsSync(r2.path), 'the sibling import\'s file must be untouched');

    const remaining = loadObservationImports(root);
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].id, second.id);

    const secondDelete = deleteObservationImport(root, first.id);
    assert.equal(secondDelete, false, 'deleting an already-gone import must report false, not throw');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/5 — importFileName + path-traversal refusal.
// =====================================================================

test('OS/5a: importFileName strips the obsimport: prefix', () => {
  assert.equal(importFileName('obsimport:0123456789ab'), '0123456789ab.json');
});

test('OS/5b: importFileName returns null for every malformed id shape', () => {
  for (const bad of [null, '', 'obsimport:', 'snapshot:0123456789ab', 'obsimport:XYZ', 'obsimport:0123456789abc']) {
    assert.equal(importFileName(bad), null, `expected null for ${JSON.stringify(bad)}`);
  }
});

test('OS/5c: path-traversal refusal — loadObservationImport/deleteObservationImport never escape the store directory', () => {
  const root = makeTempProject();
  try {
    // A file planted OUTSIDE the store, at exactly the location a naive
    // (guard-free) path.join(dir, importId.slice(...) + '.json') would
    // resolve to for 'obsimport:../../x' — this makes the test a real
    // regression guard, not a vacuous one: if the shape guard in
    // importFileName were ever removed, this planted file would come back
    // instead of null.
    const plantedPath = path.join(root, 'x.json');
    fs.writeFileSync(plantedPath, JSON.stringify(baseImport()));

    assert.equal(loadObservationImport(root, '../../../etc/passwd'), null);
    assert.equal(loadObservationImport(root, 'obsimport:../../x'), null,
      'a traversal-shaped id must never resolve to the planted file outside the store');

    assert.equal(deleteObservationImport(root, '../../../etc/passwd'), false);
    assert.equal(deleteObservationImport(root, 'obsimport:../../x'), false);
    assert.ok(fs.existsSync(plantedPath), 'the planted file outside the store must never be unlinked');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/6 — persistObservationImport's own refusal gates.
// =====================================================================

test('OS/6a: persistObservationImport refuses when the state dir is unsafe, and creates no .agentic-security/ directory at all', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-obs-store-unsafe-'));
  try {
    assert.equal(isSafeStateDir(observationsDir(root)), false, 'precondition: a marker-less temp dir must be unsafe');
    const result = persistObservationImport(root, baseImport());
    assert.equal(result.ok, false);
    assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
    assert.equal(fs.existsSync(path.join(root, '.agentic-security')), false,
      'a refused write must never create the state directory as a side effect');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/6b: persistObservationImport refuses when stateWritesEnabled() is false', () => {
  const root = makeTempProject();
  const priorEnabled = stateWritesEnabled();
  try {
    setStateWritesEnabled(false);
    const result = persistObservationImport(root, baseImport());
    assert.equal(result.ok, false);
    assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
    assert.equal(fs.existsSync(path.join(root, '.agentic-security', 'runtime-observations')), false);
  } finally {
    setStateWritesEnabled(priorEnabled);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/7 — the store as the last line of defense.
// =====================================================================

test('OS/7a: persistObservationImport refuses an import whose observations[] contains an invalid RuntimeObservation, and writes nothing', () => {
  const root = makeTempProject();
  try {
    const badObservation = { ...baseObservation(), eventCountBand: 'not-a-real-band' };
    const record = baseImport({ observations: [badObservation] });

    const result = persistObservationImport(root, record);
    assert.equal(result.ok, false);
    assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
    assert.equal(loadObservationImports(root).length, 0,
      'no path may exist by which an unvalidated observation reaches disk');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/7b: validateObservationImport is closed-world at the import level too — an unknown top-level key is an error', () => {
  const valid = baseImport();
  const { valid: validOk } = validateObservationImport(valid);
  assert.equal(validOk, true, 'precondition: the base fixture must itself be valid');

  const withUnknownKey = { ...valid, rawTrace: 'some raw telemetry blob' };
  const result = validateObservationImport(withUnknownKey);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.path === '$.rawTrace'), JSON.stringify(result.errors));
});

// =====================================================================
// OS/8 — the AC-29 clause 5 artifact-level proof, end to end.
// =====================================================================

test('OS/8: a persisted clean import never carries a forbidden substring on disk; a payload-derived import is refused and the store is unchanged', () => {
  const root = makeTempProject();
  try {
    const cleanText = fs.readFileSync(path.join(FIXTURES_DIR, 'native-clean.jsonl'), 'utf8');
    const payloadText = fs.readFileSync(path.join(FIXTURES_DIR, 'native-payload.jsonl'), 'utf8');

    const { drafts: cleanDrafts, errors: cleanErrors } = parseNativeJsonlObservations(cleanText, fixtureContext());
    assert.equal(cleanErrors.length, 0);
    assert.ok(cleanDrafts.length > 0);

    const cleanImport = baseImport({ observations: draftsToObservations(cleanDrafts) });
    const { valid: cleanValid } = validateObservationImport(cleanImport);
    assert.equal(cleanValid, true, 'precondition: the clean-fixture-derived import must itself validate');

    const cleanResult = persistObservationImport(root, cleanImport);
    assert.equal(cleanResult.ok, true, JSON.stringify(cleanResult));

    const rawOnDisk = fs.readFileSync(cleanResult.path, 'utf8');
    const forbidden = ['payload', 'prompt', 'response', 'SELECT', '4111111111111111', '123-45-6789', 'http.url', 'db.statement'];
    for (const substr of forbidden) {
      assert.ok(!rawOnDisk.includes(substr), `the clean import's on-disk bytes must never contain "${substr}"`);
    }

    // Direction two: the payload fixture's three wire-layer-clean-but-
    // attribute-layer-dirty lines (http.url / db.statement attribute KEYS,
    // plus B1's schema.name-carrying-a-SQL-statement VALUE smuggling
    // attempt through an APPROVED key) must be refused at
    // validateRuntimeObservation, so the whole import is refused and the
    // store stays exactly as it was.
    const { drafts: payloadDrafts, errors: payloadErrors } = parseNativeJsonlObservations(payloadText, fixtureContext());
    assert.equal(payloadErrors.length, 2, 'precondition: exactly 2 of the 5 payload lines are caught at the wire layer (AD/4a)');
    assert.equal(payloadDrafts.length, 3, 'precondition: exactly 3 lines pass the wire layer and reach RuntimeObservation validation');

    const payloadImport = baseImport({ importedAt: '2026-08-31T14:00:00.000Z', observations: draftsToObservations(payloadDrafts) });
    const { valid: payloadValid } = validateObservationImport(payloadImport);
    assert.equal(payloadValid, false, 'the payload-derived import must fail validateObservationImport (unapproved attribute keys)');

    const payloadResult = persistObservationImport(root, payloadImport);
    assert.equal(payloadResult.ok, false);

    const stillOnlyClean = loadObservationImports(root);
    assert.equal(stillOnlyClean.length, 1, 'the store must be unchanged — still only the clean import');
    assert.equal(stillOnlyClean[0].id, cleanImport.id);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/9 — encryption wiring (Correction 1).
// =====================================================================

test('OS/9a: with no encryption policy, plaintext round-trips; with {provider: local-key}, the on-disk file is a real encrypted envelope that still round-trips', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      const plainRecord = baseImport({ importedAt: '2026-08-31T09:00:00.000Z' });
      const plainResult = persistObservationImport(root, plainRecord);
      assert.equal(plainResult.ok, true, JSON.stringify(plainResult));
      const plainRaw = fs.readFileSync(plainResult.path, 'utf8');
      assert.equal(isEncryptedEnvelope(JSON.parse(plainRaw)), false, 'no encryption policy configured means plaintext JSON on disk');
      const plainLoaded = loadObservationImports(root).find((i) => i.id === plainRecord.id);
      assert.deepEqual(plainLoaded, plainRecord);

      fs.writeFileSync(path.join(root, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');

      const encRecord = baseImport({ importedAt: '2026-08-31T10:00:00.000Z' });
      const encResult = persistObservationImport(root, encRecord);
      assert.equal(encResult.ok, true, JSON.stringify(encResult));
      const encRaw = fs.readFileSync(encResult.path, 'utf8');
      const encParsed = JSON.parse(encRaw);
      assert.equal(isEncryptedEnvelope(encParsed), true,
        'confidential: true in the registry is a claim nothing backs without this test — with a provider configured, the on-disk file must be a real encrypted envelope');
      assert.ok(!encRaw.includes(encRecord.id), 'the plaintext import id must not be visible in the on-disk envelope');

      const decrypted = JSON.parse(maybeDecryptForRead(encRaw));
      assert.deepEqual(decrypted, encRecord);

      const encLoaded = loadObservationImports(root).find((i) => i.id === encRecord.id);
      assert.deepEqual(encLoaded, encRecord, 'loadObservationImports must still round-trip the plaintext record transparently');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('OS/9b: with {provider: null, required: true}, persistObservationImport fails closed and writes nothing', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
      fs.writeFileSync(path.join(root, '.agentic-security', ENCRYPTION_POLICY_FILE), 'required: true\n');
      const record = baseImport();
      const result = persistObservationImport(root, record);
      assert.equal(result.ok, false);
      assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
      assert.equal(loadObservationImports(root).length, 0);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// =====================================================================
// OS/10 — read-time tolerance.
// =====================================================================

test('OS/10a: a corrupt or non-.json file in the store directory is skipped; the other imports still load', () => {
  const root = makeTempProject();
  try {
    const good = baseImport();
    const result = persistObservationImport(root, good);
    assert.equal(result.ok, true, JSON.stringify(result));

    const dir = observationsDir(root);
    fs.writeFileSync(path.join(dir, 'corrupt.json'), '{ not valid json [[[');
    fs.writeFileSync(path.join(dir, 'notes.txt'), 'this is not a json file at all');

    const imports = loadObservationImports(root);
    assert.equal(imports.length, 1);
    assert.equal(imports[0].id, good.id);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('OS/10b: an import file whose content fails validateObservationImport on read is skipped, never returned', () => {
  const root = makeTempProject();
  try {
    const good = baseImport();
    const result = persistObservationImport(root, good);
    assert.equal(result.ok, true, JSON.stringify(result));

    const dir = observationsDir(root);
    const hand = { ...baseImport({ importedAt: '2026-08-31T15:00:00.000Z' }), someUnvalidatedField: 'planted by hand' };
    const handFileName = importFileName(hand.id);
    fs.writeFileSync(path.join(dir, handFileName), JSON.stringify(hand));

    const imports = loadObservationImports(root);
    assert.equal(imports.length, 1, 'a file nobody validated on write must not become trusted by being on disk');
    assert.equal(imports[0].id, good.id);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// =====================================================================
// OS/11 — I1 (final review): signing, and the forged-import repro.
// =====================================================================

test('OS/11a: a real import written through persistObservationImport carries a real .sig sibling that verifies, and loads normally', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      const good = baseImport();
      const result = persistObservationImport(root, good);
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.ok(fs.existsSync(`${result.path}.sig`), 'persistObservationImport must write a sibling .sig');

      const imports = loadObservationImports(root);
      assert.equal(imports.length, 1);
      assert.deepEqual(imports[0], good);
      assert.deepEqual(loadObservationImport(root, good.id), good);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('OS/11b (I1): a hand-planted import file with NO .sig sibling is refused as untrusted — indistinguishable from a real forged import — even when it is otherwise perfectly well-formed', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      // First write a real, signed import so the directory is genuinely
      // safe to write into (mkdirSync side effect), then hand-plant a
      // SECOND, perfectly well-formed import with no .sig at all —
      // mirroring the reviewer's own exact repro: a hand-crafted file
      // naming a real flow's ids with a fabricated matchMethod/
      // matchConfidence, accepted on read before this fix because
      // structural validation alone cannot tell it apart from a real one.
      const real = persistObservationImport(root, baseImport());
      assert.equal(real.ok, true, JSON.stringify(real));

      const forged = baseImport({ importedAt: '2026-08-31T16:00:00.000Z' });
      const { valid } = validateObservationImport(forged);
      assert.equal(valid, true, 'precondition: the forged file must be structurally perfect — that is exactly the attack this fix defeats');
      const dir = observationsDir(root);
      const forgedFileName = importFileName(forged.id);
      fs.writeFileSync(path.join(dir, forgedFileName), JSON.stringify(forged, null, 2));
      // Deliberately NO .sig written for the forged file.

      const imports = loadObservationImports(root);
      assert.equal(imports.length, 1, 'only the real, signed import may load — the unsigned forgery must be refused');
      assert.equal(imports[0].id, baseImport().id);
      assert.equal(loadObservationImport(root, forged.id), null, 'loadObservationImport must also refuse the unsigned forgery directly');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('OS/11c (I1): a hand-planted import file with a .sig that does NOT verify (tampered, or signed under a different key) is refused', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      const real = persistObservationImport(root, baseImport());
      assert.equal(real.ok, true, JSON.stringify(real));

      const forged = baseImport({ importedAt: '2026-08-31T17:00:00.000Z' });
      const dir = observationsDir(root);
      const forgedFileName = importFileName(forged.id);
      const forgedContent = JSON.stringify(forged, null, 2);
      fs.writeFileSync(path.join(dir, forgedFileName), forgedContent);
      // A .sig that verifies against DIFFERENT content — the shape a real
      // signature file has, but for the wrong bytes (tampered post-sign,
      // or signed by a different install's key).
      fs.writeFileSync(path.join(dir, `${forgedFileName}.sig`), signLastScan('not the real content'));

      const imports = loadObservationImports(root);
      assert.equal(imports.length, 1, 'a .sig that fails verification must refuse the import exactly like a missing one');
      assert.equal(imports[0].id, baseImport().id);
      assert.equal(loadObservationImport(root, forged.id), null);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

test('OS/11d (I1): a tampered import — real .sig present but the .json body edited after signing — is refused', () => {
  withIsolatedXdgHome(() => {
    const root = makeTempProject();
    try {
      const good = baseImport();
      const result = persistObservationImport(root, good);
      assert.equal(result.ok, true, JSON.stringify(result));

      // Tamper the on-disk body AFTER signing — the .sig now verifies
      // against stale content, never the bytes actually on disk.
      const tampered = { ...good, source: 'tampered-source' };
      fs.writeFileSync(result.path, JSON.stringify(tampered, null, 2));

      assert.equal(loadObservationImports(root).length, 0, 'a tampered body must be refused, never silently trusted');
      assert.equal(loadObservationImport(root, good.id), null);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
