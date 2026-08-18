// PRD T1.2 — the shared cross-framework auth resolver, and the FastAPI
// missing-auth rule that now consults it.
//
// The regression this pins is a measured one. On the 2026-08-17 independent
// population, GHSA-3cg5-48j3-v4gv scored a "true positive" for
//   "FastAPI mutating endpoint create_folder() has no Security() / Depends()
//    auth dependency"
// against a handler that declares `user=Depends(get_verified_user)` and calls
// `await check_folders_permission(request, user, db=db)` on its first line.
// The claim was false about the code it described. It scored only because the
// harness matched on CWE + file and an unrelated fix 200 lines away carried
// the same CWE.
//
// Both directions matter and both are pinned below: the rule must stop
// asserting an absence the file contradicts, AND must still fire on a handler
// that genuinely has no protection. A precision fix that silences the true
// positives too is not a fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { routeAuthEvidence, hasAuthInParams, hasAuthInBody } from '../src/sast/_auth-signals.js';
import { scanFastapiHardening } from '../src/sast/fastapi-hardening.js';

const fastapi = (body) => 'from fastapi import APIRouter, Depends, Request\n\nrouter = APIRouter()\n\n' + body;

// ───────────────────────────────────────── the resolver itself
test('a project-specific Depends() callee is recognised, not just blessed names', () => {
  // get_verified_user is in nobody's enumeration; the SHAPE is what counts.
  const e = hasAuthInParams('request: Request, form_data: FolderForm, user=Depends(get_verified_user)');
  assert.ok(e, 'expected auth evidence');
  assert.match(e.reason, /dependency-injected auth/);
});

test('a bare Security(...) counts regardless of what it wraps', () => {
  assert.ok(hasAuthInParams('token = Security(anything_at_all)'));
});

test('an auth-shaped parameter name counts', () => {
  assert.ok(hasAuthInParams('user: User'));
  assert.ok(hasAuthInParams('current_user'));
});

test('an ordinary handler signature carries NO auth evidence', () => {
  assert.equal(hasAuthInParams('request: Request, form_data: FolderForm'), null);
  assert.equal(hasAuthInParams('item_id: int, db: AsyncSession = Depends(get_async_session)'), null);
  assert.equal(hasAuthInParams(''), null);
});

test('a body-level authorization call counts (the half that was missing)', () => {
  const e = hasAuthInBody('    await check_folders_permission(request, user, db=db)\n    return 1\n');
  assert.ok(e, 'expected body auth evidence');
  assert.match(e.reason, /explicit authorization call/);
});

test('a body raising an explicit 403 counts', () => {
  assert.ok(hasAuthInBody('if user.role != "admin":\n    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)\n'));
});

test('an ordinary body carries NO auth evidence', () => {
  assert.equal(hasAuthInBody('    items = await Items.get_all(db=db)\n    return items\n'), null);
  // A non-auth call with an action-shaped prefix must not be mistaken for one.
  assert.equal(hasAuthInBody('    validate_payload(form_data)\n'), null);
});

test('routeAuthEvidence accepts evidence from EITHER half', () => {
  assert.ok(routeAuthEvidence({ params: 'user=Depends(get_verified_user)', body: '' }));
  assert.ok(routeAuthEvidence({ params: 'request: Request', body: 'await require_admin(user)\n' }));
  assert.equal(routeAuthEvidence({ params: 'request: Request', body: 'return 1\n' }), null);
});

// ───────────────────────────────────────── the detector, end to end
test('REGRESSION: the real GHSA-3cg5 handler shape no longer fires', () => {
  const src = fastapi([
    '@router.post("/")',
    'async def create_folder(',
    '    request: Request,',
    '    form_data: FolderForm,',
    '    user=Depends(get_verified_user),',
    '    db: AsyncSession = Depends(get_async_session),',
    '):',
    '    await check_folders_permission(request, user, db=db)',
    '    folder = await Folders.get_folder_by_parent_id_and_user_id_and_name(',
    '        form_data.parent_id, user.id, form_data.name, db=db',
    '    )',
    '    return folder',
  ].join('\n'));
  const missingAuth = scanFastapiHardening('routers/folders.py', src)
    .filter(f => f.family === 'fastapi-missing-auth');
  assert.deepEqual(missingAuth, [], `must not claim this handler is unauthenticated: ${JSON.stringify(missingAuth.map(f => f.vuln))}`);
});

test('POSITIVE CONTROL: a genuinely unauthenticated mutating handler still fires', () => {
  const src = fastapi([
    '@router.post("/danger")',
    'async def wipe_everything(request: Request, form_data: WipeForm):',
    '    await Everything.delete_all()',
    '    return {"ok": True}',
  ].join('\n'));
  const missingAuth = scanFastapiHardening('routers/danger.py', src)
    .filter(f => f.family === 'fastapi-missing-auth');
  assert.equal(missingAuth.length, 1, 'the unprotected handler must still be reported');
  assert.equal(missingAuth[0].cwe, 'CWE-862');
  assert.ok(missingAuth[0].checkedFor, 'an absence-claim must record what it looked for (T2.2)');
});

test('body evidence is scoped to the handler, not borrowed from the next one', () => {
  // The FIRST handler is unprotected; the SECOND one does the auth check.
  // Before body-scoping, the second handler's check could mask the first.
  const src = fastapi([
    '@router.post("/open")',
    'async def open_endpoint(request: Request):',
    '    return await Data.all()',
    '',
    '@router.post("/closed")',
    'async def closed_endpoint(request: Request):',
    '    await require_permission(request)',
    '    return await Data.all()',
  ].join('\n'));
  const hits = scanFastapiHardening('routers/mixed.py', src)
    .filter(f => f.family === 'fastapi-missing-auth');
  assert.equal(hits.length, 1, `expected exactly the unprotected handler, got ${JSON.stringify(hits.map(h => h.vuln))}`);
  assert.match(hits[0].vuln, /open_endpoint/);
});
