// PRD Theme 5 — FIXTURE-FIRST rebuild from real vulnerable code.
//
// The first version of this detector was written from the root-cause PRD's
// PROSE ("reads customerId from req.query and forwards it to identityManager")
// and produced ZERO findings on the very entry it was designed from. Measured:
// all five new detector families were silent across the whole population.
//
// These fixtures are copied VERBATIM from
// bench/independent/cache/GHSA-2364-jh4q-m9vm (Flowise, CWE-639), pre/ and
// post/, so the rule is written against code that really shipped rather than
// against a summary of it. The cache is gitignored, so the snippets are
// inlined here — that is the point of a fixture.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanOwnershipAuthz } from '../src/sast/ownership-authz.js';

// Verbatim from pre/ — the vulnerable revision.
const PRE = [
  '    public async getCustomerWithDefaultSource(req: Request, res: Response, next: NextFunction) {',
  '        try {',
  '            const { customerId } = req.query',
  "            if (!customerId) {",
  "                return res.status(400).json({ error: 'Customer ID is required' })",
  '            }',
  '            const identityManager = getRunningExpressApp().identityManager',
  '            const result = await identityManager.getCustomerWithDefaultSource(customerId as string)',
  '',
  '            return res.status(StatusCodes.OK).json(result)',
  '        } catch (error) {',
  '            next(error)',
  '        }',
  '    }',
].join('\n');

// Verbatim from post/ — the upstream fix adds one ownership assertion.
const POST = PRE.replace(
  '            const identityManager = getRunningExpressApp().identityManager',
  '            assertStripeIdMatchesSession(customerId as string, req.user?.activeOrganizationCustomerId)\n'
  + '            const identityManager = getRunningExpressApp().identityManager');

test('REAL CODE: the vulnerable revision is reported', () => {
  const f = scanOwnershipAuthz('organization.controller.ts', PRE);
  assert.ok(f.length > 0,
    'the rule must fire on the code it was designed from — it previously returned 0 here');
  assert.equal(f[0].cwe, 'CWE-639');
});

test('REAL CODE: the upstream fix silences it (fix-discrimination)', () => {
  assert.deepEqual(scanOwnershipAuthz('organization.controller.ts', POST), [],
    'the ownership assertion the maintainers added is the control this rule looks for');
});

test('the id is recognised through DESTRUCTURING, not just member access', () => {
  // `const { customerId } = req.query` is what the real code does; the first
  // version only matched `req.query.customerId`.
  const f = scanOwnershipAuthz('c.ts', [
    'async function h(req, res) {',
    '  const { orderId } = req.params',
    '  return await billing.fetchOrderDetails(orderId)',
    '}',
  ].join('\n'));
  assert.equal(f.length, 1, 'destructured ids must be recognised');
});

test('a DOMAIN method counts as a use — not only findOne/get/update', () => {
  // The real sink is identityManager.getCustomerWithDefaultSource(...), which
  // matches no generic ORM verb list.
  const f = scanOwnershipAuthz('c.ts', [
    'async function h(req, res) {',
    '  const { subscriptionId } = req.query',
    '  return await identityManager.getAdditionalSeatsQuantity(subscriptionId)',
    '}',
  ].join('\n'));
  assert.equal(f.length, 1);
});

test('REFUSES: responding with the id is not acting on it', () => {
  assert.deepEqual(scanOwnershipAuthz('c.ts', [
    'async function h(req, res) {',
    '  const { orderId } = req.query',
    '  return res.status(400).json({ error: orderId })',
    '}',
  ].join('\n')), [], 'res.*/log calls are not object access');
});

// Second real entry: GHSA-r745-8hwv-h473 (Flowise oauth2 routes). Found via a
// near-miss sweep of the independent population — this handler was flagged
// ownership-missing even though it scopes its lookup by `workspaceId`, taken
// from the request's own session via getActiveWorkspaceIdForRequest(req).
// Workspace/tenant scoping IS an ownership check at a coarser grain; T5.1
// only checked OWNERSHIP_RE (req.user/current_user/ownerId:), so it couldn't
// see it. Verbatim from bench/independent/cache/GHSA-r745-8hwv-h473/pre.
const TENANT_SCOPED_PRE = [
  "router.post('/authorize/:credentialId', async (req: Request, res: Response, next: NextFunction) => {",
  '    try {',
  '        const { credentialId } = req.params',
  '        const workspaceId = getActiveWorkspaceIdForRequest(req)',
  '',
  '        const appServer = getRunningExpressApp()',
  '        const credentialRepository = appServer.AppDataSource.getRepository(Credential)',
  '',
  '        let credential = await credentialRepository.findOneBy({',
  '            id: credentialId,',
  '            workspaceId',
  '        })',
  '    } catch (error) {',
  '        next(error)',
  '    }',
  '})',
].join('\n');

// The sibling handler in the SAME real file, unchanged — genuinely unscoped,
// and must still fire. Distinguishes "tenant scoping suppresses this" from
// "TENANT_RE anywhere in the file suppresses everything."
const UNSCOPED_SIBLING = [
  "router.post('/refresh/:credentialId', async (req: Request, res: Response, next: NextFunction) => {",
  '    try {',
  '        const { credentialId } = req.params',
  '        const appServer = getRunningExpressApp()',
  '        const credentialRepository = appServer.AppDataSource.getRepository(Credential)',
  '',
  '        const credential = await credentialRepository.findOneBy({',
  '            id: credentialId',
  '        })',
  '    } catch (error) {',
  '        next(error)',
  '    }',
  '})',
].join('\n');

test('REAL CODE: workspace/tenant scoping counts as an ownership check', () => {
  assert.deepEqual(scanOwnershipAuthz('index.ts', TENANT_SCOPED_PRE), [],
    'a lookup scoped by workspaceId (from the request session) is guarded, not vulnerable');
});

test('REAL CODE: a sibling handler with NO scoping at all still fires', () => {
  const f = scanOwnershipAuthz('index.ts', UNSCOPED_SIBLING);
  assert.ok(f.some(x => x.subfamily === 'ownership-missing'));
});
