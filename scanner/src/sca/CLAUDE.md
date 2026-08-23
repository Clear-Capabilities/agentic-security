# scanner/src/sca/

Software Composition Analysis. Detects vulnerable dependencies (OSV + KEV
+ EPSS), dependency confusion, typosquats, vendored copies, deprecated
components, and EOL container base images. Reads manifests in 11
ecosystems and the most common lockfiles in each.

Most of the SCA *pipeline* lives in `../engine.js` (the manifest dispatch
in `parseManifests`, OSV/KEV/EPSS enrichment, attack-path computation).
This directory holds the seven specialized modules called from there.

## Modules

| Module | Purpose |
|---|---|
| `index.js` | Re-exports six public symbols from `../engine.js` so external consumers can `import { parseManifests, queryOSV, … } from '@…/sca'`. |
| `binary-metadata.js` | **Opt-in via `AGENTIC_SECURITY_BINARY_SCA=1`.** Reads dependency metadata from compiled artifacts: JAR `META-INF/MANIFEST.MF` + `pom.properties`, Go binary `go.buildinfo`. Never executes the binary. JAR extraction uses `fs.mkdtemp` for an isolated scratch dir (premortem-derived: shared `/tmp` lets a hostile JAR plant a symlinked manifest that escapes the scratch). |
| `container.js` | Dockerfile parser. Detects EOL `FROM` base images (alpine/debian/ubuntu/node/python) against `base-images.json`, and synthesizes lightweight SCA components from `apt-get install` / `apk add` package lists. No Docker daemon required. |
| `dep-confusion.js` | Two related detectors. **Typosquat:** Damerau-Levenshtein distance against `popular-packages.json`, accepted only when `distance / min(nameLen, popularLen) ≤ 0.25` — **188 packages (115 npm + 73 pypi), not "top-1000"** as this row previously said; re-derive the count from the file rather than trusting a hardcoded number here again. **Dependency confusion:** internal-scoped names (declared in `.agentic-security/internal-scopes.yml`) appearing on the public registry. Local-first; **this module does not itself call OSV** — it reads a flag set by an earlier, separate OSV/queryRegistries pass upstream (whether a dep "resolved by OSV"), which is different from "OSV consulted [by this module] to confirm confusion findings" as previously stated. |
| `llm-function-extract.js` | **Opt-in via `AGENTIC_SECURITY_LLM_SCA=1`.** LLM-assisted extraction of vulnerable function names for CVEs that lack OSV `ecosystem_specific.vulnerable_functions` data. Cached per CVE under `~/.config/agentic-security/llm-sca-cache/`. Endpoint-dependent — degrades to no-op when unreachable. |
| `py-package-functions.js` | **Opt-in via `AGENTIC_SECURITY_DEEP=1`** (Python only). Locates installed Python packages via `site-packages` and parses them with the CPython `ast` module (subprocess) to *validate* that an OSV-named vulnerable function exists in the installed version. Closes the "OSV says this function is vulnerable, but the version you installed actually removed it" false-positive class. |
| `vendor-detect.js` | Detects libraries copied into `src/` (lodash, jQuery, Angular, React, etc.) via characteristic version strings and function signatures. Catches the case where a vulnerable library bypasses the lockfile because someone vendored it directly. |

## Data sources + caches

| Source | Cache location | TTL | Trigger |
|---|---|---:|---|
| OSV.dev `/v1/querybatch` | `~/.claude/agentic-security/osv-cache/` (sha256-keyed JSON blobs) | session | every SCA-enabled scan |
| OSV.dev `/v1/vulns/{id}` | same | session | per unique vuln id from querybatch |
| CISA KEV catalog | same, key `kev:catalog` | 24h | first SCA finding per scan |
| FIRST.org EPSS | same, key `epss:<CVE>` | session | batched (100 CVEs / request — see `engine.js:_fetchEPSSBatch`) |
| PyPI registry | session | session | `queryRegistries` for deprecated/yanked/inactive checks |
| npm registry | session | session | fallback deprecation lookup |
| OSV.dev licenses | repo-level fetch | per dep | license-policy enforcement |

All network access degrades gracefully when offline
(`AGENTIC_SECURITY_OFFLINE=1` forces this on); missing data results in
incomplete fields, never a hard failure.

## Manifest + lockfile dispatch

The PARSERS table in `engine.js#parseManifests` maps basename →
`_parseXxx` function. As of Phase 1 of the SCA improvement plan
(commit `f8a4c3e`):

| Ecosystem | Direct deps | Transitive deps |
|---|---|---|
| npm | `package.json` | `package-lock.json` ✓, `yarn.lock` ✓, `pnpm-lock.yaml` ✓ |
| pypi | `requirements.txt`, `pyproject.toml`, `Pipfile` | `poetry.lock` ✓, `Pipfile.lock` ✓ |
| packagist | `composer.json` | `composer.lock` ✓ |
| rubygems | `Gemfile` | `Gemfile.lock` ✓ |
| golang | `go.mod` | `go.sum` ✓ (Phase 1) |
| cargo | `Cargo.toml` | `Cargo.lock` ✓ |
| maven | `pom.xml` (+ `<properties>` substitution + `<dependencyManagement>` BOM labelling, Phase 1) | `dependency-tree.txt` ✓ (Phase 1) — output of `mvn dependency:tree -DoutputFile=…` |
| maven (gradle) | `build.gradle`, `build.gradle.kts` | **not transitive** — Gradle dependency graph deferred per project policy |
| pub (Dart/Flutter) | `pubspec.yaml` | `pubspec.lock` ✓ |
| system (Conan) | `conanfile.txt` (regex) | `conan.lock` ✓ (Phase 1, both Conan 1.x and 2.x) |
| system (vcpkg) | `vcpkg.json` | `vcpkg-configuration.json` ✓ (Phase 1, overlay registries) |
| system (CMake) | `CMakeLists.txt` | n/a — Conan / vcpkg are the real lockfile surface |

## Finding shape (supplyChain bucket)

Each SCA finding lives in `scan.supplyChain` (kept separate from
`scan.findings` which is the SAST array). Required + commonly-set fields:

```javascript
{
  type: 'vulnerable_dep' | 'unpinned_dep' | 'no_lockfile',
  name, version, ecosystem, group, scope, purl, file,
  // OSV enrichment
  osvId, cveAliases: ['CVE-…'], description, fixedVersions: ['…'],
  severity, cvssVector, hasKnownAttackRef,
  osvVulnFunctions: ['module.fn', '…'],
  // Reachability
  reachable: true | false,
  functionReachable: 'reachable' | 'unreachable' | 'unknown',
  reachabilityTier: 'function-reachable' | 'import-reachable'
                  | 'build-only' | 'manifest-only' | 'transitive-only',
  // Risk overlays (added by posture annotators)
  kev, kevDateAdded, kevRansomware, weaponized,
  epssScore, epssPercentile, exploitedNow,
  toxicityScore, toxicityLabel,
  // Composite (Phase 1)
  compositeRisk: 0..100,
  compositeRiskTier: 'critical' | 'high' | 'medium' | 'low' | 'minimal',
  compositeRiskFactors: ['…'],
  // Provenance
  pomSource: 'direct' | 'managed' | 'dependency-tree',
  isTransitive: true | false,
  isUnpinned: boolean,
  // Dedup
  dependents: [], _transitiveDeduped: int,
}
```

`parser` + `family` defaults are backfilled by `posture/finding-defaults.js`
if a detector forgets to set them.

## Conventions specific to this directory

- **No detector executes downloaded code.** Manifest parsing only.
  `binary-metadata.js` calls the `jar` CLI tool but only with extract-only
  flags into an isolated scratch dir.
- **Opt-in flags.** `AGENTIC_SECURITY_BINARY_SCA`, `AGENTIC_SECURITY_DEEP`,
  `AGENTIC_SECURITY_LLM_SCA` all default off. Each module documents its
  own activation gate.
- **No new dependencies.** Maven / Conan / vcpkg use inline regex /
  JSON parsing — `fast-xml-parser` was deliberately not added (premortem:
  bundle-size + audit-surface concern).
- **Network fan-out.** OSV `/v1/querybatch` accepts 1000-package batches;
  EPSS accepts ~100 CVEs per `?cve=` URL; OSV vuln-details has no batch
  endpoint so it's parallelized with a concurrency cap of 20
  (`engine.js#queryOSV`).
- **Cache hits are session-storage backed.** `_osvCacheGet` /
  `_osvCacheSet` route through a disk-backed shim
  (`engine.js:145`) into `~/.claude/agentic-security/osv-cache/`.

## Gotchas

- **`type: 'vulnerable_dep'` lives in supplyChain, not findings.** Code
  that iterates `scan.findings` will miss every SCA finding. The report
  layer's `normalizeFindings()` is the only place they're merged.
- **`isTransitive` is detector-set when the lockfile knows.** `go.sum`,
  `dependency-tree.txt`, `conan.lock` set it. `package-lock.json` does
  not currently set it explicitly (treats every entry equivalently);
  treat that as a known limitation.
- **Function-level reachability is regex-based.** `markUsedVulnFunctions`
  scans for `funcName(` patterns in `fileContents`. False negatives on
  aliased imports (`{ vuln_fn as safeName }`) and dynamic dispatch.
- **EOL base-image detection has a hand-curated cutoff.** `base-images.json`
  is updated periodically; an alpine-3.16 today might not appear EOL until
  the file is refreshed. Bias is toward false negatives.
- **Typosquat similarity is RELATIVE, and that is load-bearing.** The rule is
  Damerau-Levenshtein ≤ 2 *and* `distance / min(len) ≤ 0.25` against
  popular-packages.json (188 entries, not top-1000).

  The absolute `Levenshtein ≤ 2` this used to be was measured by
  `bench/sca-replay` over 13 real repositories and produced **166 findings at
  critical/high, of which zero were typosquats** — `ms ~ ws`, `acorn ~ cors`,
  `ajv ~ ava`, `six ~ tox`, `arg ~ yargs`, `bail ~ babel`. All short names: two
  edits on a four-character name changes half of it, and every two-character
  package is one edit from every other. The ratio gate is what removes them.

  Damerau rather than plain Levenshtein because a TRANSPOSITION (`lodahs` for
  `lodash`) is the most common real typo, and plain distance scores it 2 — the
  same as two unrelated substitutions. Under the ratio gate that would have
  thrown the genuine cases out along with the noise.

  The FP budget is pinned in `test/dep-confusion.test.js` using the actual
  names the bench surfaced. Widening the reference list is safe *because* of
  the ratio gate; widening it under the old rule would have multiplied the
  noise.

## Adding a new detector here

1. Decide whether it fits an existing module (e.g. add a new typosquat
   variant to `dep-confusion.js`) or warrants a new file.
2. Re-export any public function from `index.js` IF external consumers
   need it; otherwise keep it private.
3. If it emits findings, set `family: 'vulnerable-dep'` (or a new family
   recognized by `posture/finding-defaults.js`) so downstream calibration
   and confidence pipelines work.
4. Add a regression test under `../../test/`. The pattern at
   `scanner/test/sca-deprecated.test.js` is the simplest model for a
   network-stubbed detector.
5. Wire the test file into `npm run test:posture` in `../../package.json`.

## Open work (tracked in the SCA improvement plan)

- Maven Gradle dependency-graph integration (currently regex-only, no
  transitives) — deferred from v1 due to Gradle shell-out fragility.
- Vulnerable-function reachability chained back to an HTTP route handler
  for SCA (Phase 2 / Item 4 — was missing at the time of Phase 1's land).
- SCA-aware remediation MCP toolchain (`synthesize_sca_upgrade` /
  `apply_sca_upgrade`) — Phase 3.
- `.agentic-security/sca-policy.yml` for per-CVE / per-package accept-risk +
  SLA — Phase 4.
