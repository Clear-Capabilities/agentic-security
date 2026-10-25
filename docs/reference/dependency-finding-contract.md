# Dependency finding: contract

<!-- seo: title="Dependency finding contract: the fields, the reachability tiers and what an empty result means" description="The fields a vulnerable dependency finding carries, the reachability tiers and triage verdicts it can report, and how a scan says it could not consult advisory data." -->

**Maturity:** GA

A dependency finding says that a component in your lockfile or manifest has a published advisory, whether the advisory is being exploited, and whether the vulnerable function is reached from your code. Dependency findings are in `supplyChain` on the scan result. Stage context: [Discover](../discover/README.md). How to read a scan: [scanning](../guides/scanning.md).

## The finding

A compatibility test (`scanner/test/contracts/dependency-finding.contract.test.js`) scans a project with seeded advisory data and holds the finding to the table below in both directions: a field cannot be added or removed without changing this page. Fields that start with an underscore are internal.

**Finding fields**

| Field | Meaning |
|---|---|
| `type` | `vulnerable_dep` |
| `name` | The package name |
| `version` | The resolved version |
| `ecosystem` | `npm`, `pypi`, `maven`, and the other ecosystems the scanner reads |
| `purl` | The package URL |
| `osvId` | The advisory identifier |
| `cveAliases` | CVE identifiers for the same advisory |
| `description` | The advisory summary |
| `fixedVersions` | Versions that fix it, possibly empty |
| `severity` | `critical`, `high`, `medium` or `low`, after the reachability tier is applied |
| `cvssVector` | The CVSS vector, or `null` |
| `hasKnownAttackRef` | `true` when the advisory links a public exploit reference |
| `osvVulnFunctions` | Functions the advisory names as vulnerable, possibly empty |
| `reachable` | Whether the package is imported by your code |
| `scope` | `required`, `optional` or `dev` |
| `file` | The manifest or lockfile the component came from |
| `filePath` | The same path, for tools that read `filePath` |
| `isDirect` | Whether your manifest names it, as opposed to a dependency of a dependency |
| `line` | A line in the file, or 0 |
| `depChain` | The chain from your manifest to the component |
| `advisory` | The advisory text with its identifier |
| `range` | The affected version range |
| `kev` | Whether the advisory is in the CISA catalog of exploited vulnerabilities |
| `weaponized` | Whether a public exploit is known |
| `kevDateAdded` | When the catalog added it, or `null` |
| `kevRansomware` | Whether the catalog notes ransomware use |
| `usedVulnerableFunctions` | Vulnerable functions your code calls |
| `vulnerableFunctionCallSites` | Where it calls them: `pkg`, `fn`, `file` and `line` |
| `functionReachable` | `reachable`, `unreachable` or `unknown` |
| `routeReachable` | Whether a call site is reached from a route handler |
| `reachabilityTier` | One of the tiers below |
| `reverseExposure` | How many files import it, how many routes reach it, and a sample of each |
| `toxicityScore` | A 0 to 100 score for the package itself |
| `toxicityFactors` | What contributed to it |
| `toxicityLabel` | The score as a word |
| `compositeRisk` | A 0 to 100 score that combines severity, exploitation, reachability and exposure |
| `compositeRiskTier` | The score as a tier |
| `compositeRiskFactors` | What contributed to it |
| `scaVerdict` | One of the verdicts below |
| `scaVerdictReason` | Why |
| `findingProvenance` | Which commit introduced the dependency, or why that is not available |

**Reachability tiers**

| Tier | Meaning |
|---|---|
| `route-reachable-via-function` | The vulnerable function is called and the call is reached from a route handler. The highest urgency |
| `function-reachable` | The vulnerable function is called, but not within four hops of a route handler |
| `unreachable` | The advisory names vulnerable functions and your code calls none of them |
| `import-reachable` | The package is imported, and the advisory names no function to check |
| `build-only` | The package is optional or build-time and not imported. Severity is lowered one step |
| `manifest-only` | The package is required and declared, and nothing imports it |
| `transitive-only` | The package is only a dependency of a dependency, and nothing imports it. It is marked unreachable |

**Triage verdicts**

| Verdict | Meaning |
|---|---|
| `AUTO_MERGE_PATCH` | A patch-level fix exists and the risk justifies taking it without review |
| `WAIT_FOR_PATCH` | No fixed version is published |
| `MANUAL_REVIEW` | A person should decide |
| `ACCEPT_RISK` | The risk is low enough to accept |
| `WONT_FIX` | Not worth fixing |

## What an empty result means

When a scan cannot consult advisory data for a dependency, because the run is offline with nothing cached or the advisory service did not answer, the scan says so in `scanHealth.freshness.advisories`:

**Advisory coverage**

| Field | Meaning |
|---|---|
| `source` | `live`, `cache`, `offline-cache-only`, `live-partial`, `unreachable` or `none-needed` |
| `componentsChecked` | Components with a version the lookup can answer for |
| `answered` | Components the lookup answered for, from the cache or live |
| `unanswered` | Components it could not answer for |

Any unanswered component makes the scan health `partial` and adds a condition that says the absence of a finding is not evidence the dependency is safe. A scan that reports no dependency findings and `partial` has not checked those dependencies.

## Rules that hold

- **Unknown is a value.** A vulnerable function that cannot be checked is `functionReachable: unknown`, never `unreachable`.
- **A demotion is recorded.** A finding lowered by its tier keeps the tier that lowered it.
- **No claim without data.** An advisory without a fix has `fixedVersions: []` and the verdict `WAIT_FOR_PATCH`.

## What this does not do

<!-- limits-verified: 2026-10-20 -->

- **It checks the versions in your files, not what runs.** A package pinned in a lockfile but replaced at deploy time is not seen.
- **Function-level reachability depends on advisory data.** Many advisories name no vulnerable function, and for those the best answer is `import-reachable`. Imports resolved through unusual module patterns can be missed.
- **Advisory data is fetched and cached.** It is as current as the last successful lookup, and the scan states when it could not look.
- **Severity can be lowered by the tier.** A `build-only` finding drops one severity step. Read `reachabilityTier` next to `severity`.
- **It does not say a vulnerability is exploitable.** `kev` and `weaponized` say others exploit it. For execution evidence use [exploit proof](../guides/exploit-proof-fabric.md).
