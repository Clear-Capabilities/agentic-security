# The finding lifecycle

<!-- seo: title="The finding lifecycle: from detector to verified fix" description="The operational workflow for working one finding, and how it nests inside the ten-stage assurance lifecycle." -->

When you work a single finding you follow the **operational finding workflow**:

`Find → Prove → Hunt → Scope → Fix → Verify → Detect`

It is a **subset of the platform lifecycle**, not a competing model. The platform lifecycle is the ten stages in [the assurance lifecycle](assurance-lifecycle.md):

`Discover → Corroborate → Prove → Learn → Scale → Observe → Trace → Fix → Verify → Detect ↻`

## How the seven steps map onto the ten stages

| Operational step | What you do | Platform stage | Maturity |
|---|---|---|---|
| **Find** | Run a scan; read the verdict and the finding's evidence | Discover, Corroborate | GA |
| **Prove** | Try to reproduce the exploit with a reproducer you supply | Prove | Preview |
| **Hunt** | Ask model lenses for what the rules missed, gated by the engine | Discover | Preview |
| **Scope** | Find sibling instances and affected repositories | Scale, Trace | Preview / Labs |
| **Fix** | Preview a patch, apply it through the verified path | Fix | GA |
| **Verify** | Read which verification legs ran and the tier | Verify | GA |
| **Detect** | Generate and validate a detection, hunt local logs | Detect | Labs (live SIEM connection: Roadmap) |

The platform stages Learn and Observe have no step here because they act across many findings or on the system, not on one finding in one sitting.

## Where to go

- The module pipeline, detector to report: [Architecture: the finding lifecycle](../architecture/finding-lifecycle.md)
- A real finding walked through every stage: [One finding's journey](../workflows/one-findings-journey.md)
- Every field on a finding: [Reading a finding's evidence](../walkthroughs/finding-evidence.md)
- Triage decisions and how they feed the next scan: [Fixing vulnerabilities](../guides/fixing-vulnerabilities.md)
