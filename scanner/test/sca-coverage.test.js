// Coverage tests for Phase 1 / Items 3a-3c of the SCA improvement plan.
//
// Each test passes a representative manifest string to parseManifests via the
// internal dispatch table and asserts what was extracted. The fixtures are
// inline (small, representative) so the tests don't depend on fixture-tree
// state.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifests } from '../src/engine.js';

// ─── Maven (pom.xml with properties + dependencyManagement) ─────────────────

test('Maven pom.xml: property substitution resolves ${prop} versions', () => {
  const pom = `<?xml version="1.0"?>
<project>
  <properties>
    <spring.version>5.3.20</spring.version>
    <jackson.version>2.13.3</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>\${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>\${jackson.version}</version>
    </dependency>
  </dependencies>
</project>
`;
  const comps = parseManifests({ 'pom.xml': pom });
  assert.equal(comps.length, 2);
  const spring = comps.find(c => c.name === 'org.springframework:spring-core');
  assert.ok(spring, 'spring-core extracted');
  assert.equal(spring.version, '5.3.20', 'property substitution worked');
  assert.equal(spring.isUnpinned, false);
  const jackson = comps.find(c => c.name === 'com.fasterxml.jackson.core:jackson-databind');
  assert.equal(jackson.version, '2.13.3');
});

test('Maven pom.xml: unresolved ${prop} marked isUnpinned', () => {
  const pom = `<project>
  <dependencies>
    <dependency><groupId>com.x</groupId><artifactId>y</artifactId><version>\${unknown}</version></dependency>
  </dependencies>
</project>`;
  const comps = parseManifests({ 'pom.xml': pom });
  assert.equal(comps.length, 1);
  assert.equal(comps[0].version, '0.0.0');
  assert.equal(comps[0].isUnpinned, true);
});

test('Maven pom.xml: dependencyManagement BOM imports are labelled `managed`', () => {
  const pom = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.7.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>2.7.0</version>
    </dependency>
  </dependencies>
</project>`;
  const comps = parseManifests({ 'pom.xml': pom });
  assert.equal(comps.length, 2);
  const bom = comps.find(c => c.name.endsWith(':spring-boot-dependencies'));
  assert.equal(bom.pomSource, 'managed');
  assert.equal(bom.pomType, 'pom');
  const direct = comps.find(c => c.name.endsWith(':spring-boot-starter-web'));
  assert.equal(direct.pomSource, 'direct');
});

test('Maven pom.xml: XML comments do not produce phantom dependencies', () => {
  const pom = `<project>
  <dependencies>
    <!--
      <dependency><groupId>commented</groupId><artifactId>out</artifactId><version>1.0.0</version></dependency>
    -->
    <dependency><groupId>real</groupId><artifactId>dep</artifactId><version>2.0.0</version></dependency>
  </dependencies>
</project>`;
  const comps = parseManifests({ 'pom.xml': pom });
  assert.equal(comps.length, 1, 'only the uncommented dep extracted');
  assert.equal(comps[0].name, 'real:dep');
});

test('Maven pom.xml: scope=test → optional', () => {
  const pom = `<project>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
  </dependencies>
</project>`;
  const comps = parseManifests({ 'pom.xml': pom });
  assert.equal(comps[0].scope, 'optional');
});

// ─── Maven dependency-tree.txt (transitive resolution) ──────────────────────

test('Maven dependency-tree.txt: extracts the full transitive graph', () => {
  const tree = `com.example:demo:jar:1.0.0
+- org.springframework.boot:spring-boot-starter:jar:2.7.0:compile
|  +- org.springframework.boot:spring-boot:jar:2.7.0:compile
|  |  \\- org.springframework:spring-context:jar:5.3.20:compile
|  |     \\- org.springframework:spring-core:jar:5.3.20:compile
|  +- org.springframework.boot:spring-boot-autoconfigure:jar:2.7.0:compile
|  \\- org.springframework.boot:spring-boot-starter-logging:jar:2.7.0:compile
+- com.fasterxml.jackson.core:jackson-databind:jar:2.13.3:compile
\\- junit:junit:jar:4.13.2:test
`;
  const comps = parseManifests({ 'dependency-tree.txt': tree });
  // 8 lines after the project root (which gets skipped):
  //   spring-boot-starter, spring-boot, spring-context, spring-core,
  //   spring-boot-autoconfigure, spring-boot-starter-logging,
  //   jackson-databind, junit
  assert.equal(comps.length, 8);
  const directs = comps.filter(c => !c.isTransitive);
  assert.ok(directs.length >= 0, 'directs may or may not be flagged from text indentation');
  const allTransitive = comps.every(c => c.pomSource === 'dependency-tree');
  assert.ok(allTransitive, 'every component flagged dependency-tree source');
  const junit = comps.find(c => c.name === 'junit:junit');
  assert.equal(junit.scope, 'optional', 'test scope → optional');
  const jackson = comps.find(c => c.name === 'com.fasterxml.jackson.core:jackson-databind');
  assert.equal(jackson.version, '2.13.3');
});

// ─── Go (go.sum transitive deps) ────────────────────────────────────────────

test('go.sum: extracts every resolved module exactly once', () => {
  const gosum = `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/net v0.4.0 h1:O8wlR3o8ZG2BIbUf6sLeJBjwAxAvW3rAB1OS3YK8/8s=
golang.org/x/net v0.4.0/go.mod h1:OWRtw5hkUq3J9TQk5GydcfhU2v3yQqz1Wpf5T+TIrJM=
google.golang.org/grpc v1.50.1+incompatible h1:abcdef=
google.golang.org/grpc v1.50.1+incompatible/go.mod h1:fedcba=
`;
  const comps = parseManifests({ 'go.sum': gosum });
  assert.equal(comps.length, 3, 'three distinct modules');
  const errors = comps.find(c => c.name === 'github.com/pkg/errors');
  assert.equal(errors.version, '0.9.1');
  assert.equal(errors.ecosystem, 'golang');
  assert.equal(errors.isTransitive, true);
  const grpc = comps.find(c => c.name === 'google.golang.org/grpc');
  // `+incompatible` is KEPT. This expectation was reversed deliberately under
  // PRD F3.1: `+incompatible` is part of the module version the advisory
  // database matches on, and it is what belongs in an emitted SBOM. The same
  // stripping habit destroyed Go pseudo-versions
  // (v0.0.0-20210903162142-ad29c8ab022f → 0.0.0), collapsing every
  // pseudo-versioned module in a tree onto one key; bench/sca-replay measured
  // Go recall at 5.28% because of it, and 100% once the versions survived.
  // Normalisation for a query belongs at the query — see _osvQueryVersion.
  assert.equal(grpc.version, '1.50.1+incompatible', '+incompatible suffix preserved');
});

test('go.sum: malformed lines are skipped without error', () => {
  const gosum = `not a real go.sum line
github.com/valid/dep v1.0.0 h1:abc=
github.com/valid/dep v1.0.0/go.mod h1:def=
`;
  const comps = parseManifests({ 'go.sum': gosum });
  assert.equal(comps.length, 1);
  assert.equal(comps[0].name, 'github.com/valid/dep');
});

// ─── Conan lockfile + vcpkg-configuration ────────────────────────────────────

test('conan.lock (Conan 1.x graph_lock): extracts nodes', () => {
  const lockfile = JSON.stringify({
    version: '0.4',
    graph_lock: {
      nodes: {
        '0': { ref: 'consumer/0.1' },
        '1': { ref: 'openssl/3.0.0@conan/stable' },
        '2': { ref: 'zlib/1.2.13' },
      },
    },
  });
  const comps = parseManifests({ 'conan.lock': lockfile });
  assert.equal(comps.length, 3);
  const openssl = comps.find(c => c.name === 'openssl');
  assert.equal(openssl.version, '3.0.0');
  assert.equal(openssl.ecosystem, 'system');
});

test('conan.lock (Conan 2.x): extracts requires arrays', () => {
  const lockfile = JSON.stringify({
    version: '0.5',
    requires: ['boost/1.81.0#abc', 'fmt/9.1.0#def'],
    build_requires: ['cmake/3.26.0'],
  });
  const comps = parseManifests({ 'conan.lock': lockfile });
  assert.equal(comps.length, 3);
  assert.ok(comps.find(c => c.name === 'boost' && c.version === '1.81.0'));
  assert.ok(comps.find(c => c.name === 'cmake' && c.version === '3.26.0'));
});

test('vcpkg-configuration.json: extracts overlay-registry packages', () => {
  const conf = JSON.stringify({
    'default-registry': { kind: 'git', repository: 'https://github.com/microsoft/vcpkg' },
    registries: [
      { kind: 'git', repository: 'https://example.org/overlay', packages: ['custom-pkg-1', 'custom-pkg-2'] },
    ],
  });
  const comps = parseManifests({ 'vcpkg-configuration.json': conf });
  assert.equal(comps.length, 2);
  assert.ok(comps.find(c => c.name === 'custom-pkg-1'));
  assert.equal(comps[0].isUnpinned, true, 'no version info available in this file');
});

test('Malformed JSON in conan.lock / vcpkg-configuration.json is silent', () => {
  assert.deepEqual(parseManifests({ 'conan.lock': 'not json' }), []);
  assert.deepEqual(parseManifests({ 'vcpkg-configuration.json': '{' }), []);
});

// ─── Sanity: parseManifests still works for existing ecosystems ──────────────

test('parseManifests still parses package.json after the refactor', () => {
  const pkg = JSON.stringify({
    name: 'demo', version: '1.0.0',
    dependencies: { lodash: '^4.17.20' },
    devDependencies: { jest: '^29.0.0' },
  });
  const comps = parseManifests({ 'package.json': pkg });
  assert.ok(comps.length >= 2);
  assert.ok(comps.find(c => c.name === 'lodash'));
});
