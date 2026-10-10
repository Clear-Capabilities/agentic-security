# Deployment-aware support

Deployment-aware analysis reads the configuration a service is deployed with and uses it to qualify findings from the source: is the code behind a public entry point, does anything deny the path, does the identity running it hold a privilege worth reaching. It is **off by default** and **only claimed for the adapters listed below as validated**. This page says what is validated, how that was decided, and what is reported separately because it is not established.

Every figure on this page comes from a **synthetic** test set: cases written by the people who wrote the tool, with labels nobody independent adjudicated. The figures check a mechanism on constructed cases. They are not engine accuracy and they are not evidence of benefit on real programs. A real-code gate refuses this set by design.

## Turning it on

The feature is `deployment-boundaries`. Enable it for one run with `AGENTIC_SECURITY_ASSURANCE_DEPLOYMENT_BOUNDARIES=1`, or in `.agentic-security/assurance.yml`. With it off, a scan, a report and every other command behave exactly as before.

```bash
agentic-security boundaries --from deploy/ --findings .agentic-security/last-scan.json --out boundaries.json --json
```

`--from` is a directory of deployment files. Besides the configuration it may hold `service-bindings.json` (an array of `{ "pathPrefix", "service" }`, tying a finding's file to a deployed service), `identities.json` (policy file to the identity it belongs to) and `traces.jsonl` (sanitized runtime trace lines). The command reads local files only, runs nothing and contacts nothing. The only write is the file named by `--out`.

| Exit code | Meaning |
|---|---|
| 0 | A report was produced. Findings the configuration could not assess are in it, marked as such. |
| 1 | The run failed: unreadable or invalid input, a scan result whose signature does not verify, ingest refused, or `--out` refused. |
| 2 | Usage error. |
| 3 | The feature is off, blocked or unsupported on this platform. Nothing was read. |

## Validated adapters

A deployment-aware claim is made for an adapter only when the frozen ablation set holds a positive fixture (an exploitable deployment the graph keeps) and a negative fixture (a non-exploitable deployment the graph does not report), with no baseline confirmed defect lost. The release check for this page recomputes the table below from the set.

| Adapter | Status | Basis |
|---|---|---|
| `kubernetes` | validated | positive and negative fixtures, no baseline defect lost |
| `compose` | validated | positive and negative fixtures, no baseline defect lost |
| `terraform-plan` | not validated | no fixture in the frozen set uses this adapter |
| `iam-policy` | not validated | no fixture in the frozen set uses this adapter |

`terraform-plan` and `iam-policy` still ingest, and their relationships still appear in a boundary graph. They are not covered by any deployment-aware claim until fixtures exist for them.

## What the synthetic evaluation measured

Seven cases, each the same source deployed two ways (14 instances): a public ingress versus an internal-only service, a published port versus an internal network, an ingress whose target the supplied files do not fully resolve, a finding with no service binding, and three admin-service cases that differ in reachability, in privilege, or in a gateway authentication setting the adapters do not read. Two arms were scored on the same instances: `source-only` (every scan finding is reported) and `graph-enabled` (the same findings qualified by the boundary context, plus a deployment-exposure finding when an exposed entry reaches a privileged resource).

| Arm | True positives | False positives | Missed | Precision | Recall |
|---|---|---|---|---|---|
| source-only | 4 | 4 | 3 | 50.0% | 57.1% |
| graph-enabled | 7 | 2 | 0 | 77.8% | 100.0% |

Paired over the 14 instances:

| Paired count | Value |
|---|---|
| False positives the graph reduced | 3 |
| Confirmed defects the graph added | 3 |
| Baseline confirmed defects the graph lost | 0 |
| False positives the graph added | 1 |
| Instances unchanged | 7 |

The one false positive the graph added is a case where an external authentication setting protects the route and the adapters do not read it. That is a known limit, left in the set on purpose. A finding with no service binding is kept, so that case gets no benefit either.

Uncertainty is a simple paired case bootstrap (cases resampled with both of their instances, fixed seed, 4000 resamples). It is not the grouped bootstrap the accuracy report calls for, which this build does not contain. With seven cases the intervals are wide: the precision difference is +27.8 points with a 95% interval of 13.6 to 50.0, and the recall difference is +42.9 points with an interval of 14.3 to 85.7. Treat them as exploratory.

Runtime is reported by the evaluation (`npm run evaluation -- deployment-ablation`) as wall-clock milliseconds on the machine that ran it. It is not part of the frozen comparison. On the development machine building the boundary graph and the contexts added a median of roughly one to two milliseconds per instance on top of a scan that took a few hundred; those figures are machine dependent.

How the set is protected: each case's source tree, each deployment tree, the labels and the graph arm's decision rule are hash-pinned in `scanner/test/fixtures/deployment-ablation/frozen.json` and bound into the evaluation protocol. A changed file, label or rule is refused before anything is measured. One case (the unresolved ingress) exists because an earlier version of the rule lost a defect on it; the rule was tightened to keep any finding whose graph has a gap. The set therefore is not blind with respect to the rule, which is one more reason not to read it as an estimate.

## Unresolved and stale coverage, reported separately

These are never folded into the counts above.

- **Unresolved**: a graph gap (for example an ingress target whose manifest was not supplied), an unresolved node, a finding with no service binding, or an exposure the configuration leaves unresolved. In the set: 1 instance has a graph gap, and 2 findings were not tied to a service. A gap stops the graph arm from treating "no path found" as "no exposure".
- **Stale**: an ingested source whose content no longer matches the digest recorded at ingest, or that is missing. In the set: 0 stale and 0 missing sources. Stale or missing sources must be re-ingested before the relationships they supported are trusted.
- **Traces**: the set contains no runtime traces, so observed, sampled and stale trace coverage are all unmeasured here. Traffic coverage is never established by any supplied observation.

## What is not claimed

- No claim of benefit on real programs, no claim of accuracy, and no claim that a finding with no path is safe: "no path found" means the supplied files did not show one.
- No exploitability from reachability. A path is possible, blocked or unresolved; only an applicable trusted verification record makes a finding exploitable in its scenario.
- No adapter beyond the validated ones above, no ingress annotation or gateway authentication semantics, and no explicit network deny from Kubernetes network policies (a policy narrows what is allowed; the adapters do not turn the absence of an allow into a deny).
