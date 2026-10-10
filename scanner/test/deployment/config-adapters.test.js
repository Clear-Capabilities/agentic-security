// X-302: ingest deployment and identity configuration. Local, customer-supplied
// files only; no network, no credentials, no execution of configuration.
// Each criterion is tested with a good input that must produce the relation and
// a bad or hostile input that must produce a typed gap and no invented edge.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { digestOfBytes } from '../../src/posture/assurance/identity.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import {
  ingestDeploymentConfig, ingestDeploymentFiles, invalidateChangedSources, detectFormat, resolveUnderRoot, ADAPTER_NAMES, DEPLOYMENT_FEATURE, MAX_INGEST_FILES,
} from '../../src/lineage/deployment/ingest.js';
import { validateBoundaryGraph, buildBoundaryGraph, exportBoundaryGraph } from '../../src/lineage/deployment/boundary-graph.js';
import { fx, ingestOne, ingestText, nodeByName, edgesOf } from './helpers.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, '..', '..', 'src', 'lineage', 'deployment');

function gapCodes(g) { return g.gaps.map(x => x.code); }
function substantiveEdges(g) { return g.edges.filter(e => !['deployed-in', 'defined-in', 'scoped-to'].includes(e.relation)); }

// ------------------------------------------------------------------ AC01

test('[X-302.AC01] Kubernetes manifests become services, routes, identities, grants and network edges', () => {
  const g = ingestOne('k8s-payments/manifests.yaml', { repository: 'payments', as: 'k8s/manifests.yaml' });
  assert.equal(validateBoundaryGraph(g).ok, true);
  // workload -> identity -> grant
  assert.equal(edgesOf(g, 'assumes', { from: 'payments/api', to: 'sa/payments/payments-sa' }).length, 1);
  const grant = edgesOf(g, 'grants', { from: 'sa/payments/payments-sa', to: 'k8s/ns:payments/configmaps' })[0];
  assert.equal(grant.effect, 'allow');
  assert.equal(grant.discriminator, 'get,list');
  // ingress -> service object -> workload, so an entry point reaches a workload
  assert.equal(edgesOf(g, 'routes-to', { from: 'ingress/payments/public:pay.example.com/v1', to: 'svc/payments/api' })[0].pathState, 'possible');
  assert.equal(edgesOf(g, 'routes-to', { from: 'svc/payments/api', to: 'payments/api' })[0].pathState, 'possible');
  assert.equal(nodeByName(g, 'ingress/payments/public:pay.example.com/v1').trustZone, 'public');
  // network policy: only api may reach ledger, and ledger records that it is isolated
  assert.equal(edgesOf(g, 'network-allows', { from: 'payments/api', to: 'payments/ledger' }).length, 1);
  assert.equal(nodeByName(g, 'payments/ledger').attrs.ingressPolicy, 'restricted');
  // tenant label becomes a tenant node and a scoped-to edge
  assert.ok(nodeByName(g, 'acme', 'tenant'));
  assert.equal(nodeByName(g, 'payments/api').tenant, 'acme');
  // repository and environment are first class
  assert.ok(nodeByName(g, 'payments', 'repository') && nodeByName(g, 'prod', 'environment'));
  assert.equal(nodeByName(g, 'payments/api').repository, 'payments');
});

test('[X-302.AC01] compose files become services, published-port entry routes and declared dependencies', () => {
  const g = ingestOne('compose/docker-compose.yml', { repository: 'shop', environment: 'dev', as: 'docker-compose.yml' });
  assert.equal(nodeByName(g, 'port/web:8080').trustZone, 'public');
  assert.equal(nodeByName(g, 'port/web:9090').trustZone, 'internal', 'a loopback bind is not public');
  assert.equal(edgesOf(g, 'routes-to', { from: 'port/web:8080', to: 'web' }).length, 1);
  assert.equal(edgesOf(g, 'depends-on', { from: 'web', to: 'api' })[0].pathState, 'possible');
  assert.equal(edgesOf(g, 'depends-on', { from: 'api', to: 'db' }).length, 1, 'object form of depends_on is read');
  assert.equal(edgesOf(g, 'calls').length, 0, 'a dependency is never recorded as a call');
  assert.equal(nodeByName(g, 'api').tenant, 'acme');
  assert.equal(nodeByName(g, 'db').attrs.networkInternal, true);
});

test('[X-302.AC01] a Terraform plan JSON becomes identities, grants, a workload identity and a public network allow', () => {
  const g = ingestOne('terraform/plan.json', { repository: 'infra', as: 'plan.json' });
  const allow = edgesOf(g, 'grants', { from: 'iam-role/app-role' }).find(e => e.effect === 'allow');
  assert.equal(allow.discriminator, 's3:GetObject,s3:PutObject');
  assert.equal(allow.pathState, 'possible');
  const deny = edgesOf(g, 'grants', { from: 'iam-role/app-role' }).find(e => e.effect === 'deny');
  assert.equal(deny.pathState, 'blocked');
  const sg = edgesOf(g, 'network-allows', { to: 'sg/web-sg' })[0];
  assert.equal(nodeByName(g, 'cidr/0.0.0.0/0').trustZone, 'public');
  assert.equal(sg.discriminator, 'tcp:443-443');
  assert.ok(nodeByName(g, 's3/app-data'));
});

test('[X-302.AC01] a standalone IAM policy document is attached to the identity the caller names', () => {
  const g = ingestOne('iam/policy.json', { repository: 'infra', as: 'orders.json', identities: { 'orders.json': 'orders-svc' } });
  assert.ok(edgesOf(g, 'grants', { from: 'iam/orders-svc' }).length >= 2);
  assert.ok(nodeByName(g, 'iam/orders-svc').resolved);
});

test('[X-302.AC01] Gateway API HTTPRoute is read as a public route to a Service', () => {
  const g = ingestText([{ path: 'gw.yaml', text: [
    'apiVersion: gateway.networking.k8s.io/v1', 'kind: HTTPRoute', 'metadata: {name: r, namespace: web}',
    'spec:', '  parentRefs: [{name: edge-gw}]', '  hostnames: [shop.example.com]', '  rules:', '    - matches: [{path: {value: /cart}}]', '      backendRefs: [{name: cart, port: 80}]',
  ].join('\n') }]);
  const route = nodeByName(g, 'httproute/web/r:shop.example.com/cart');
  assert.equal(route.trustZone, 'public');
  assert.equal(route.attrs.gateways, 'edge-gw');
  assert.equal(edgesOf(g, 'routes-to', { from: route.name })[0].pathState, 'unresolved', 'the backend Service is not in the bundle');
});

test('[X-302.AC01] configuration is never executed: a code tag is refused, nothing is evaluated, and the adapters import no execution primitive', () => {
  const g = ingestOne('unsupported/code-tag.yaml', { as: 'code-tag.yaml' });
  assert.equal(g.nodes.length, 0);
  assert.equal(g.edges.length, 0);
  assert.deepEqual(gapCodes(g), ['malformed-input']);
  // policy strings are data: an interpolation stays literal text and is not expanded
  const tfText = JSON.stringify({ format_version: '1.2', resource_changes: [{ address: 'aws_s3_bucket.b', type: 'aws_s3_bucket', change: { actions: ['create'], after: { bucket: '${env.SECRET}-data' }, after_unknown: {} } }] });
  const t = ingestText([{ path: 'p.json', text: tfText }]);
  assert.ok(nodeByName(t, 's3/${env.SECRET}-data'), 'taken literally');
  for (const f of fs.readdirSync(SRC).filter(n => n.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(SRC, f), 'utf8');
    assert.ok(!/child_process|node:vm|from 'vm'|\beval\(|new Function\(|node:http|node:https|node:net|node:dns|node:dgram|\bfetch\(/.test(text), `${f} imports or uses an execution or network primitive`);
  }
});

test('[X-302.AC01] credentials and secret objects in the input never reach the graph', () => {
  const k8s = JSON.stringify(ingestOne('k8s-payments/manifests.yaml', { as: 'm.yaml' }));
  assert.ok(!k8s.includes('hunter2') && !k8s.includes('never-appear') && !k8s.includes('DB_PASSWORD'));
  const compose = JSON.stringify(ingestOne('compose/docker-compose.yml', { as: 'c.yml' }));
  assert.ok(!compose.includes('compose-secret') && !compose.includes('API_TOKEN') && !compose.includes('db.env'));
});

test('[X-302.AC01] the same files ingested for two environments share no node or edge', () => {
  const prod = ingestOne('compose/docker-compose.yml', { environment: 'prod', as: 'c.yml' });
  const stg = ingestOne('compose/docker-compose.yml', { environment: 'staging', as: 'c.yml' });
  // a repository is not environment scoped, so it is the one node the two graphs may share
  const ids = new Set(prod.nodes.map(n => n.id));
  assert.deepEqual(stg.nodes.filter(n => ids.has(n.id)).map(n => n.kind), ['repository']);
  const eids = new Set(prod.edges.map(e => e.id));
  assert.equal(stg.edges.filter(e => eids.has(e.id)).length, 0);
});

test('[X-302.AC01] more files than the cap are not all read, and the cut is reported', () => {
  const files = Array.from({ length: MAX_INGEST_FILES + 5 }, (_, i) => ({ path: `f${String(i).padStart(4, '0')}.yml`, text: `services:\n  s${i}: {}\n` }));
  const r = ingestDeploymentConfig({ files, environment: 'prod', repository: 'r' });
  assert.equal(r.status, 'ok');
  assert.equal(r.graph.sources.length, MAX_INGEST_FILES);
  assert.ok(r.graph.gaps.some(g => g.code === 'limit-exceeded' && /only the first/.test(g.message)));
});

test('[X-302.AC01] invalid ingest input is refused with a typed result, not a guessed environment', () => {
  const f = [{ path: 'a.yaml', text: 'x: 1' }];
  for (const bad of [{ environment: undefined }, { environment: 'has space' }, { environment: 'prod', repository: 'bad repo' }, { environment: 'prod', revision: 'main' }]) {
    const r = ingestDeploymentConfig({ files: f, ...bad });
    assert.equal(r.status, 'invalid-input', JSON.stringify(bad));
    assert.equal(r.graph, null);
  }
  assert.equal(ingestDeploymentConfig({ files: 'nope', environment: 'prod' }).status, 'invalid-input');
});

// ------------------------------------------------------------------ AC02

test('[X-302.AC02] positive edge: an ingress path resolves through a Service to a workload with no gap on that chain', () => {
  const g = ingestOne('k8s-payments/manifests.yaml', { as: 'm.yaml' });
  const chain = [edgesOf(g, 'routes-to', { from: 'ingress/payments/public:pay.example.com/v1' })[0], edgesOf(g, 'routes-to', { from: 'svc/payments/api' })[0]];
  assert.ok(chain.every(e => e && e.pathState === 'possible' && e.provenance === 'static-config'));
  assert.ok(!g.gaps.some(x => /payments\/api\b/.test(x.subject) && x.code !== 'unresolved-identity') );
});

test('[X-302.AC02] conflicting configuration: an allow and a deny for the same grant is a gap, the allow is unresolved, the deny is kept', () => {
  const g = ingestOne('iam/policy.json', { as: 'orders.json', identities: { 'orders.json': 'orders-svc' } });
  assert.ok(gapCodes(g).includes('conflicting-configuration'));
  const grants = edgesOf(g, 'grants', { from: 'iam/orders-svc' }).filter(e => e.discriminator === 'dynamodb:PutItem');
  assert.equal(grants.length, 2);
  assert.equal(grants.find(e => e.effect === 'allow').pathState, 'unresolved');
  assert.equal(grants.find(e => e.effect === 'deny').pathState, 'blocked');
  // the non-conflicting read grant is untouched
  assert.equal(edgesOf(g, 'grants', { from: 'iam/orders-svc' }).find(e => e.discriminator.startsWith('dynamodb:GetItem')).pathState, 'possible');
});

test('[X-302.AC02] conflicting node declarations are recorded, not silently resolved', () => {
  const a = { kind: 'service', name: 's', environment: 'prod', trustZone: 'public', attrs: { port: '80' } };
  const b = { kind: 'service', name: 's', environment: 'prod', trustZone: 'internal', attrs: { port: '81' } };
  const r = buildBoundaryGraph({ nodes: [a, b] });
  assert.equal(r.ok, true);
  assert.equal(r.graph.nodes[0].trustZone, 'unknown');
  assert.equal(r.graph.nodes[0].attrs.port, undefined);
  assert.equal(r.graph.gaps.filter(x => x.code === 'conflicting-configuration').length, 2);
});

test('[X-302.AC02] unresolved identity: a missing ServiceAccount, Service, Role or post-apply value stays explicit and never becomes a resolved edge', () => {
  const g = ingestOne('k8s-payments/manifests.yaml', { as: 'm.yaml' });
  const sa = nodeByName(g, 'sa/payments/ledger-sa');
  assert.equal(sa.resolved, false);
  assert.match(sa.unresolvedReason, /not in the supplied manifests/);
  assert.equal(edgesOf(g, 'assumes', { from: 'payments/ledger' })[0].pathState, 'unresolved');
  assert.equal(edgesOf(g, 'routes-to', { to: 'svc/payments/not-here' })[0].pathState, 'unresolved');
  assert.equal(nodeByName(g, 'svc/payments/not-here').resolved, false);
  assert.ok(g.gaps.some(x => x.code === 'unresolved-identity' && /orphan/.test(x.subject)), 'a selector that matches nothing is a gap');

  const tf = ingestOne('terraform/plan.json', { as: 'plan.json' });
  assert.equal(nodeByName(tf, 'iam-role/aws_iam_role.pending').resolved, false);
  assert.equal(edgesOf(tf, 'assumes', { from: 'lambda/worker' })[0].pathState, 'unresolved');

  const role = ingestText([{ path: 'rb.yaml', text: ['apiVersion: rbac.authorization.k8s.io/v1', 'kind: RoleBinding', 'metadata: {name: b, namespace: n}', 'roleRef: {kind: Role, name: missing}', 'subjects: [{kind: ServiceAccount, name: s, namespace: n}]'].join('\n') }]);
  const grant = edgesOf(role, 'grants')[0];
  assert.equal(grant.pathState, 'unresolved');
  assert.equal(grant.confidence, 'low');

  const comp = ingestOne('compose/docker-compose.yml', { as: 'c.yml' });
  assert.equal(nodeByName(comp, 'cache').resolved, false);
});

test('[X-302.AC02] unsupported syntax: Terraform HCL, proxy configuration, a code tag, NotAction and merge keys are typed gaps that add no edge', () => {
  const g = ingestDeploymentConfig({ environment: 'prod', repository: 'infra', files: [
    { path: 'main.tf', text: fx('unsupported/main.tf') },
    { path: 'nginx.conf', text: fx('unsupported/nginx.conf') },
    { path: 'code-tag.yaml', text: fx('unsupported/code-tag.yaml') },
  ] });
  assert.equal(g.status, 'ok');
  assert.equal(g.graph.nodes.length, 0);
  assert.equal(g.graph.edges.length, 0);
  assert.deepEqual(g.files.map(f => f.status).sort(), ['malformed-input', 'unsupported-syntax', 'unsupported-syntax']);
  assert.match(g.graph.gaps.find(x => x.subject === 'main.tf').message, /terraform show -json/);

  const tf = ingestOne('terraform/plan.json', { as: 'plan.json' });
  assert.ok(tf.gaps.some(x => x.code === 'unsupported-syntax' && /NotAction/.test(x.message)));
  assert.ok(tf.gaps.some(x => x.code === 'unsupported-format' && /aws_cloudfront_distribution/.test(x.message)));

  const merge = ingestText([{ path: 'c.yml', text: ['x-base: &base', '  image: x', 'services:', '  a:', '    <<: *base'].join('\n') }]);
  assert.ok(merge.gaps.some(x => x.code === 'unsupported-syntax' && /merge key/.test(x.message)));

  const bomb = ingestDeploymentConfig({ environment: 'prod', files: [{ path: 'k.yaml', text: `${'a: &x 1\n'}${Array.from({ length: 150 }, () => 'b: *x').join('\n')}\nkind: Pod\napiVersion: v1\n` }] });
  assert.ok(bomb.graph.gaps.some(x => x.code === 'unsupported-syntax' && /aliases/.test(x.message)));
  assert.equal(bomb.graph.edges.length, 0);
});

test('[X-302.AC02] hostile and malformed inputs never throw and never invent an edge', () => {
  const hostile = ['', 'null', '[]', '{"a":1}', '\u0000\u0001', '{"format_version":"1","resource_changes":[null,1,"x",{"address":5}]}', '{"Statement":"nope"}',
    'apiVersion: v1\nkind: Service\nmetadata: {name: 1}\n', 'services: 5', 'services:\n  a: 7\n', '{'.repeat(2000), '__proto__: {x: 1}\nservices:\n  __proto__: {}\n'];
  for (const text of hostile) for (const ext of ['.json', '.yaml']) {
    const r = ingestDeploymentConfig({ environment: 'prod', repository: 'r', files: [{ path: `h${ext}`, text }] });
    assert.equal(r.status, 'ok', `status for ${JSON.stringify(text.slice(0, 20))}`);
    assert.equal(({}).polluted, undefined);
    assert.equal(substantiveEdges(r.graph).length, 0, `no edge may come from ${JSON.stringify(text.slice(0, 20))}`);
  }
  assert.equal(detectFormat('x', 'x').adapter, null);
  assert.deepEqual([...ADAPTER_NAMES].sort(), ['compose', 'iam-policy', 'kubernetes', 'terraform-plan']);
});

// ------------------------------------------------------------------ AC03

test('[X-302.AC03] every imported relation names the exact file, its digest, the parser and its version, and the revision', () => {
  const text = fx('k8s-payments/manifests.yaml');
  const rev = '9'.repeat(40);
  const g = ingestDeploymentConfig({ files: [{ path: 'k8s/m.yaml', text }, { path: 'c/docker-compose.yml', text: fx('compose/docker-compose.yml') }], environment: 'prod', repository: 'r', revision: rev }).graph;
  assert.ok(g.edges.length > 20);
  const expected = { 'k8s/m.yaml': digestOfBytes(Buffer.from(text, 'utf8')), 'c/docker-compose.yml': digestOfBytes(Buffer.from(fx('compose/docker-compose.yml'), 'utf8')) };
  for (const e of g.edges) {
    assert.ok(e.source, `edge ${e.id} has a source`);
    assert.equal(e.source.digest, expected[e.source.file], 'digest is of the exact bytes parsed');
    assert.ok(['kubernetes-manifest', 'compose-file'].includes(e.source.parser));
    assert.equal(e.source.parserVersion, '1');
    assert.equal(e.sourceRevision, rev);
  }
  assert.deepEqual(g.sources.map(s => s.file), ['c/docker-compose.yml', 'k8s/m.yaml']);
  for (const n of g.nodes.filter(n => n.resolved)) assert.ok(n.declaredBy.length >= 1, `${n.name} is attributed to a file`);
});

test('[X-302.AC03] a source reference with a malformed digest, a missing parser version or an unknown field is refused', () => {
  const g = ingestOne('compose/docker-compose.yml', { as: 'c.yml' });
  const mutate = (fn) => { const c = structuredClone(g); fn(c); return validateBoundaryGraph(c); };
  assert.equal(validateBoundaryGraph(g).ok, true);
  assert.equal(mutate(c => { c.edges[0].source.digest = 'sha256:short'; }).ok, false);
  assert.equal(mutate(c => { delete c.edges[0].source.parserVersion; }).ok, false);
  assert.equal(mutate(c => { c.edges[0].source.contents = 'x'; }).ok, false);
});

test('[X-302.AC03] a changed source file invalidates exactly the relations it supported', () => {
  const k8s = fx('k8s-payments/manifests.yaml'), compose = fx('compose/docker-compose.yml');
  const g = ingestDeploymentConfig({ files: [{ path: 'k8s.yaml', text: k8s }, { path: 'compose.yml', text: compose }], environment: 'prod', repository: 'r' }).graph;
  const digestOf = (t) => digestOfBytes(Buffer.from(t, 'utf8'));
  const same = { 'k8s.yaml': digestOf(k8s), 'compose.yml': digestOf(compose) };
  const unchanged = invalidateChangedSources(g, same);
  assert.equal(unchanged.ok, true);
  assert.equal(unchanged.graph, g, 'nothing changed, nothing rebuilt');
  assert.deepEqual(unchanged.invalidatedEdgeIds, []);

  const changed = invalidateChangedSources(g, { ...same, 'k8s.yaml': digestOf(`${k8s}\n# edited`) });
  assert.equal(changed.ok, true, JSON.stringify(changed.errors));
  assert.deepEqual(changed.staleFiles, ['k8s.yaml']);
  const k8sEdges = g.edges.filter(e => e.source?.file === 'k8s.yaml').map(e => e.id);
  const composeEdges = g.edges.filter(e => e.source?.file === 'compose.yml').map(e => e.id);
  assert.deepEqual([...changed.invalidatedEdgeIds].sort(), [...k8sEdges].sort());
  assert.ok(changed.graph.edges.every(e => e.source?.file !== 'k8s.yaml'));
  assert.deepEqual(changed.graph.edges.filter(e => e.source?.file === 'compose.yml').map(e => e.id).sort(), [...composeEdges].sort());
  assert.ok(changed.graph.gaps.some(x => x.code === 'source-changed' && x.file === 'k8s.yaml'));
  assert.ok(!changed.graph.sources.some(s => s.file === 'k8s.yaml'));
  assert.equal(validateBoundaryGraph(changed.graph).ok, true);
  assert.equal(nodeByName(changed.graph, 'payments/api'), undefined, 'a node only the changed file declared is gone');

  const removed = invalidateChangedSources(g, { 'compose.yml': digestOf(compose) });
  assert.ok(removed.graph.gaps.some(x => x.code === 'source-missing' && x.file === 'k8s.yaml'));
});

test('[X-302.AC03] invalidating a file that declared a node other files still reference leaves it unresolved, not silently resolved', () => {
  const a = `apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api, namespace: n}\nspec:\n  template:\n    metadata: {labels: {app: api}}\n    spec: {containers: []}\n`;
  const b = `apiVersion: v1\nkind: Service\nmetadata: {name: api, namespace: n}\nspec: {selector: {app: api}}\n`;
  const g = ingestDeploymentConfig({ files: [{ path: 'deploy.yaml', text: a }, { path: 'svc.yaml', text: b }], environment: 'prod' }).graph;
  assert.equal(g.nodes.find(n => n.name === 'n/api' && n.kind === 'service').resolved, true);
  const r = invalidateChangedSources(g, { 'deploy.yaml': digestOfBytes(Buffer.from('changed')), 'svc.yaml': g.sources.find(s => s.file === 'svc.yaml').digest });
  const w = r.graph.nodes.find(n => n.name === 'n/api' && n.kind === 'service');
  assert.ok(!w || w.resolved === false);
});

test('[X-302.AC03] the file ingest entry point is inert unless the feature is on, and a kill switch beats the flag', () => {
  const root = mkTestTmp('x302-');
  fs.writeFileSync(path.join(root, 'c.yml'), fx('compose/docker-compose.yml'));
  const args = { root, paths: ['c.yml'], environment: 'prod', repository: 'r' };
  const off = ingestDeploymentFiles({ config: resolveAssuranceConfig({ scanRoot: root, env: {} }), ...args });
  assert.equal(off.status, 'disabled');
  assert.equal(off.graph, undefined);
  const on = ingestDeploymentFiles({ config: resolveAssuranceConfig({ scanRoot: root, env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' } }), ...args });
  assert.equal(on.status, 'ok', JSON.stringify(on));
  assert.ok(on.graph.edges.length > 0);
  assert.equal(on.feature, DEPLOYMENT_FEATURE);
  const killed = ingestDeploymentFiles({ config: resolveAssuranceConfig({ scanRoot: root, env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1', AGENTIC_SECURITY_NO_DEPLOYMENT_BOUNDARIES: '1' } }), ...args });
  assert.equal(killed.status, 'blocked');
  assert.equal(killed.code, 'kill-switch');
  assert.equal(on.graph.sources[0].file, 'c.yml');
});

test('[X-302.AC03] the file entry point reads only regular files under the root: traversal, absolute paths, symlinks and oversize files are refused', () => {
  const root = mkTestTmp('x302r-');
  const outside = mkTestTmp('x302o-');
  fs.writeFileSync(path.join(outside, 'secret.yml'), 'services:\n  leak: {}\n');
  fs.writeFileSync(path.join(root, 'ok.yml'), fx('compose/docker-compose.yml'));
  fs.symlinkSync(path.join(outside, 'secret.yml'), path.join(root, 'link.yml'));
  fs.writeFileSync(path.join(root, 'big.yml'), `services:\n  a: {}\n#${'x'.repeat(2048)}\n`);
  assert.equal(resolveUnderRoot(root, '../x'), null);
  assert.equal(resolveUnderRoot(root, path.join(outside, 'secret.yml')), null);
  assert.equal(resolveUnderRoot(root, 'link.yml'), null);
  assert.equal(resolveUnderRoot(root, 'missing.yml'), null);
  // a symlinked directory component is as dangerous as a symlinked file
  fs.mkdirSync(path.join(outside, 'dir'));
  fs.writeFileSync(path.join(outside, 'dir', 'inner.yml'), 'services:\n  leak2: {}\n');
  fs.symlinkSync(path.join(outside, 'dir'), path.join(root, 'dirlink'));
  assert.equal(resolveUnderRoot(root, 'dirlink/inner.yml'), null);
  assert.ok(resolveUnderRoot(root, 'ok.yml'));
  const config = resolveAssuranceConfig({ scanRoot: root, env: { AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES: '1' }, overrides: { limits: { maxFileBytes: 1024 } } });
  const r = ingestDeploymentFiles({ config, root, paths: ['ok.yml', '../x', 'link.yml', 'big.yml'], environment: 'prod' });
  assert.equal(r.status, 'ok');
  assert.ok(!JSON.stringify(r.graph).includes('leak'));
  const reasons = r.graph.gaps.map(g => `${g.code}:${g.subject}`);
  assert.ok(reasons.includes('malformed-input:../x') && reasons.includes('malformed-input:link.yml'));
  assert.ok(reasons.includes('limit-exceeded:big.yml'));
  assert.deepEqual(r.graph.sources.map(s => s.file), ['ok.yml']);
});

test('[X-302.AC03] ingest makes no network call and opens no socket', async () => {
  const realFetch = globalThis.fetch;
  let called = 0;
  globalThis.fetch = () => { called += 1; throw new Error('network is not allowed'); };
  try {
    ingestOne('k8s-payments/manifests.yaml', { as: 'm.yaml' });
    ingestOne('terraform/plan.json', { as: 'p.json' });
    exportBoundaryGraph(ingestOne('compose/docker-compose.yml', { as: 'c.yml' }));
  } finally { globalThis.fetch = realFetch; }
  assert.equal(called, 0);
});
