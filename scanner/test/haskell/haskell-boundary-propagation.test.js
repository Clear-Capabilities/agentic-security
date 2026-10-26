// DAG-08: boundary contracts bound to Haskell consumers (record / monadic bindings), with unresolved higher-order constructs exposed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { runTaintEngine } from '../../src/dataflow/engine.js';
import { runBoundaryTaint } from '../../src/dataflow/cross-service-taint.js';
import { createBoundaryContract, bindBoundaryContracts } from '../../src/lineage/boundary-contract.js';
import { adaptCallGraphForLineage, describeHaskellBoundaries, haskellConsumerLocations } from '../../src/lineage/haskell-view.js';

const FILES = {
  'src/Order.hs': `module Order where
import Database.PostgreSQL.Simple
import Control.Monad (forM_, mapM_)

data OrderEvt = OrderEvt { customerId :: String, displayName :: String }

handleOrder :: Connection -> OrderEvt -> IO ()
handleOrder conn evt = do
  _ <- execute_ conn (fromString ("SELECT * FROM t WHERE c = '" ++ customerId evt ++ "'"))
  return ()

runAll :: Connection -> [OrderEvt] -> IO ()
runAll conn evts = mapM_ (handleOrder conn) evts

runMany :: Connection -> [OrderEvt] -> (OrderEvt -> IO ()) -> IO ()
runMany conn evts k = forM_ evts k
`,
};

const contract = (over = {}) => createBoundaryContract({
  id: 'boundary:hs-orders', kind: 'queue', persistence: 'persisted', channel: { topic: 'orders' }, schema: { name: 'OrderEvt', version: '1' },
  producer: { service: 'api', site: null, untrustedFields: ['customer_id'] },
  consumer: { service: 'hs-worker', site: { file: 'src/Order.hs', function: 'handleOrder', param: 'evt' } },
  fieldMappings: [{ from: 'customer_id', to: 'customerId' }], declaredBy: 'ops', ...over,
});

test('a Haskell consumer record field is seeded and reaches the SQL sink, with no ordinary source in the module', () => {
  const ir = buildHaskellIR(FILES);
  assert.equal(runTaintEngine(ir.perFile, ir.callGraph, {}).length, 0);
  const res = runBoundaryTaint(ir.perFile, ir.callGraph, [contract()]);
  assert.equal(res.findings.length, 1);
  const f = res.findings[0];
  assert.equal(f.file, 'src/Order.hs');
  assert.equal(f.boundary.modeledInput, true);
  assert.equal(f.boundary.observed, false);
  assert.deepEqual(f.boundary.fields.map((x) => x.consumerField), ['customerId']);
  assert.equal(res.bindings[0].language, 'haskell');
});

test('the binding keeps the ORIGINAL Haskell location and the lineage-view location side by side', () => {
  const ir = buildHaskellIR(FILES);
  const { bindings } = bindBoundaryContracts([contract()], ir.callGraph);
  assert.equal(bindings.length, 1);
  // buildProjectIR marks the merged call graph with `haskell`; the Haskell-only builder is the same graph
  const adapted = adaptCallGraphForLineage({ ...ir.callGraph, haskell: ir.callGraph });
  const loc = haskellConsumerLocations(adapted, bindings[0]);
  assert.deepEqual(loc.original, { file: 'src/Order.hs', line: 8 });
  assert.equal(loc.view.file, 'src/Order.hs');
  assert.equal(loc.view.line, 8);
  assert.equal(loc.view.view, 'haskell-lineage');
  assert.equal(loc.view.adapted, true);
  // the shared call graph is not rewritten by the view
  assert.equal(ir.callGraph.functions.get(bindings[0].qid).hs.lineageView, undefined);
});

test('a monadic function name that does not exist is a gap, not a finding at a guessed function', () => {
  const ir = buildHaskellIR(FILES);
  const res = runBoundaryTaint(ir.perFile, ir.callGraph, [contract({ consumer: { service: 'hs-worker', site: { file: 'src/Order.hs', function: 'handleOrders', param: 'evt' } } })]);
  assert.equal(res.findings.length, 0);
  assert.equal(res.gaps[0].reason, 'function-not-found');
});

test('a record field the Haskell record type does not declare is a gap when the record is known', () => {
  const ir = buildHaskellIR({ 'src/A.hs': 'module A where\ndata Cfg = Cfg { cmd :: String }\n', 'src/B.hs': 'module B where\nimport A\nrunIt :: Cfg -> String\nrunIt c = cmd c\n' });
  const c = contract({ consumer: { service: 'w', site: { file: 'src/B.hs', function: 'runIt', param: 'c' } }, fieldMappings: [{ from: 'cmd', to: 'cmd' }, { from: 'x', to: 'nope' }] });
  const { bindings, gaps } = bindBoundaryContracts([c], ir.callGraph);
  assert.equal(bindings.length, 1);
  assert.deepEqual(bindings[0].seeds, ['c.cmd']);
  assert.deepEqual(gaps.map((g) => [g.reason, g.field]), [['field-not-in-record', 'nope']]);
});

test('unresolved higher-order constructs are exposed, resolved ones are not', () => {
  const ir = buildHaskellIR(FILES);
  const d = describeHaskellBoundaries(ir.callGraph);
  assert.equal(d.unresolvedHigherOrder.length, 1);
  assert.equal(d.unresolvedHigherOrder[0].via, 'forM_');
  assert.equal(d.unresolvedHigherOrder[0].status, 'param');
  assert.equal(d.unresolvedHigherOrder[0].line, 16);
  assert.match(d.unresolvedHigherOrder[0].function, /runMany/);
  assert.ok(!d.unresolvedHigherOrder.some((u) => /runAll/.test(u.function)), 'mapM_ over a resolved project function is resolved');
});
