# IaC coverage — scored by verdict flip, end to end

**PRD F4.3.** Infrastructure-as-code was covered by `iac-terraform.js`,
`IAC_PATTERNS` and `k8s-admission.js`, with Kubernetes, Helm, CloudFormation and
Bicep named in the PRD as the gaps — and nothing measured any of it.

## Results — engine 0.142.0

| | |
|---|---:|
| **covered (verdict flips)** | **23/26 = 88.46%** |

| format | covered | silent |
|---|---:|---:|
| terraform | 6/7 | 1 |
| kubernetes | 6/7 | 1 |
| cloudformation | 4/5 | 1 |
| bicep | 2/2 | 0 |
| helm | 2/2 | 0 |
| dockerfile | 3/3 | 0 |

All three remaining gaps are `tier: hard` — see "Headroom".

## Two design decisions that make this a real instrument

### It runs a real scan, not the detectors

IaC support in this engine has failed at **admission** twice, not at detection.
`k8s-admission` was fully implemented, wired into the dispatch and covered by
unit tests while returning zero findings through an actual scan, because the
walker never kept the file. `install-script` was the same story. A bench that
imports a detector and passes it a string would have scored both as working.

So every case is written to a temp directory at a path a project would really
use — `deploy/app.yaml`, `charts/app/values.yaml`, `infra/main.bicep` — and
scanned through `runScan`. What is measured is the product.

### It scores verdict flip, not detection count

Every control ships a **vulnerable** and a **hardened** variant, and counts as
covered only when the vulnerable one fires *and* the hardened one does not.

A rule that reports both is not detecting the control, it is detecting the
resource, and a recall-only bench cannot tell the difference. `NO-FLIP` is
reported as its own outcome, distinct from `SILENT`, because it is the worse of
the two: it looks like coverage and carries no information.

**Corollary that bit once:** a `hardened` variant must be clean of *everything*
the engine checks, not just the control under test. Matching is deliberately
coarse — any finding on the file counts, because matching on the engine's own
rule names would grade it against vocabulary it chose itself. The cost is that
an unrelated true positive on the hardened variant reads as NO-FLIP. The
hardened Dockerfile pinned its base by digest but still had no `USER` directive
and still installed an unlicensed package, so two correct findings made a
covered control look broken.

## What the first run found

First measurement: **8/14**, and the failures were not spread evenly — they were
whole formats.

| format | first run |
|---|---|
| terraform | 4/4 |
| kubernetes | 3/4 |
| dockerfile | 1/2 |
| **cloudformation** | **0/2** |
| **bicep** | **0/1** |
| **helm** | **0/1** |

`src/sast/iac-cloud-templates.js` closed them: CloudFormation (open ingress,
public bucket, publicly-reachable database, wildcard IAM), Bicep (public blob,
plaintext transit, TLS 1.0, wildcard network rules), Helm values (privileged,
root UID, host network), Dockerfile base pinning, and the one Kubernetes control
`k8s-admission.js` was silent on (a literal credential in an `env` value).

**Admission needed both gates, again.** A CloudFormation template is a `.yaml`
that no path predicate recognises, exactly like a Kubernetes manifest, so
`isCloudFormationTemplate` is a content predicate wired into `readTree` **and**
into `runFullScan`'s re-filter of the same list. Opening one and not the other
leaves the detector as dark as never writing it.

### And one false positive on the hardened configuration

Verdict-flip scoring caught something a recall bench never would.
`_ALL_FROM_RE` in `src/sca/container.js` matched a digest without capturing it,
so `FROM ubuntu@sha256:…` parsed as image `ubuntu` with no tag — and a missing
tag is treated as `latest`. **The most tightly pinned form a Dockerfile can use
was reported as "ubuntu:latest (floating tag)".**

A false positive on the hardened configuration is worse than a miss: it tells
the people who did the right thing that they did the wrong one.

## Headroom, and what is deliberately left open

The bench saturated twice — 14/14 after the first round of fixes, 22/22 after
the second. A gate that cannot fail measures nothing, which is this PRD's
governing rule, so controls were added both times.

Controls now carry a `tier`. Untiered ones are direct shapes: a literal property
with an unambiguous hardened opposite. `tier: "hard"` ones need something a
regex cannot do, and **are not expected to pass**:

| control | why it is hard |
|---|---|
| `tf-iam-wildcard-equivalent` | `Action = ["s3:*","iam:*","ec2:*"]` is wildcard-*equivalent* with no literal `"*"` — needs reasoning about what a set of actions adds up to |
| `cfn-cidr-via-parameter` | the open CIDR arrives through a Parameter default, so the literal never appears on the ingress rule |
| `k8s-no-resource-limits` | an **absence** — a container with no `resources.limits` can starve every other pod on the node, and there is no string to match |

Closing one of these should be a deliberate design decision, not a wider
pattern. `tf-sg-cidr-via-variable` was added to the same tier and **passes** —
`iac-terraform.js`'s variable resolution genuinely reaches the security-group
rule, which is worth knowing.

## Honest limits

- **Regex over template text.** No YAML or Bicep parser is added — the same
  bundle-size and audit-surface argument that already rejected an XML parser
  here. Deeply nested or heavily intrinsic-function'd templates will be missed,
  and the `hard` tier is where that shows.
- **`templates/*.yaml` in a Helm chart is not scanned.** It is Go template
  source, not YAML; matching text inside `{{ }}` would report the template
  rather than the configuration. Only `values.yaml` is read.
- **A `Dockerfile` under `build/` is never scanned.** `build/` is in the
  walker's `DEFAULT_IGNORE` as build *output*. Recorded rather than fixed:
  changing that list affects every scan and `build/` genuinely is an output
  directory for several toolchains.
- **The snippets are written here.** The control *text* is third-party — these
  are the checks every published cloud and container hardening baseline agrees
  on — but no benchmark ships code, so the instantiations are ours. That makes
  this a coverage instrument, not an accuracy one against real-world templates.

## Running it

```bash
cd scanner
npm run bench:iac-coverage
```

Offline and deterministic. `test/iac-cloud-templates.test.js` is the cheap
regression net, including the digest-pinning false positive above.
