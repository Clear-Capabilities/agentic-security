# Risk in dollars

Every finding carries a `riskDollars` field — an **expected-value estimate**
of what that finding could cost, not a measured loss. This guide covers where
the number comes from, why it starts out generic, and how to configure your
own organization's inputs so it stops being generic. Implementation:
`scanner/src/posture/risk-dollars.js`.

---

## The formula

```
EV = P(exploited) × Impact($) × ReachabilityDiscount × ConfidenceWeight
```

- **`P(exploited)`** — the finding's EPSS score if it has one (a CVE with a
  published exploit-prediction score), else a family-level base rate from a
  built-in industry table (e.g. SQL injection ≈ 0.18, hardcoded secrets ≈
  0.30).
- **`Impact($)`** — a dollar figure keyed off the finding's data classes
  (`PHI` > `PCI` > `PII` > `Confidential` > a threat-model `crownJewel` >
  `default`), from a built-in table (`PII` defaults to $250k, `default` to
  $50k) or your own override.
- **`ReachabilityDiscount`** — how reachable the finding is from an entry
  point (`route-reachable` ≈ 0.9 down to `unreachable` ≈ 0.05) — a measured
  fact about this scan, from `reachabilityTier`/`routeReachable` (SCA) or
  `relevanceTier` (SAST), never perturbed by scenario or configuration.
- **`ConfidenceWeight`** — the finding's own calibrated `confidence` (or 0.8
  if absent) — also measured, never perturbed.

The industry probability and impact tables are sourced from publicly
reported aggregates (order-of-magnitude estimates for prioritization, not an
actuarial or insurance assessment).

Every finding gets three scenarios, not just one number:

| Scenario | Probability multiplier | Impact multiplier |
|---|---|---|
| `conservative` | ×0.5 | ×0.6 |
| `base` (this is the `ev` field) | ×1.0 | ×1.0 |
| `severe` | ×1.75 | ×1.5 |

Only probability and impact are perturbed across scenarios — the two generic,
industry-wide assumptions. Reachability and confidence stay fixed, because
they're measured facts about this finding in this scan, not assumptions with
real-world spread.

---

## What ships on every finding

```json
{
  "riskDollars": {
    "ev": 2066, "prob": 0.18, "impact": 50000, "discount": 0.9, "confidenceWeight": 0.26,
    "scenarioStatus": "scenario_default",
    "range": { "low": 620, "base": 2066, "high": 5422 },
    "scenarios": { "conservative": 620, "base": 2066, "severe": 5422 },
    "assumptions": [
      "probability of exploit: 0.18 (source: built-in industry base-rate table)",
      "impact estimate: $50k (tier: default, built-in default)",
      "reachability discount: 0.9 (tier: route-reachable)",
      "confidence weight: 0.26 (measured from this scan)"
    ],
    "modelVersion": "1.0.0",
    "confidence": "low"
  }
}
```

`assumptions[]` traces every factor in the formula back to exactly which
table entry and which tier produced it — never a bare number with no
provenance. `modelVersion` lets you tell whether two scans' dollar figures
came from the same methodology. None of this ever touches `finding.severity`.

---

## Scenario disclosure — the honesty mechanism

The single most important field is **`scenarioStatus`**, because it tells
you whether the number in front of you reflects *your* organization or a
generic industry scenario. There are exactly three values, and the message
text is generated verbatim by the engine (not paraphrased here):

**`scenario_default`** — nothing configured:

> Uses generic industry-wide scenario defaults. No organization-specific
> inputs are configured (see .agentic-security/risk-config.yml) — this is
> NOT a likely-organizational-loss estimate.

**`scenario_partially_configured`** — some but not all of the five required
inputs are set:

> Uses organization-configured values for: `<configured inputs>`. Still
> missing for a likely-organizational-loss estimate: `<missing inputs>`.
> This is NOT a likely-organizational-loss estimate.

**`scenario_organization_specific`** — all five required inputs are set:

> All organization-specific inputs are configured (impactUSD,
> organizationScale, industry, recordCount, controlStrength) — this estimate
> reflects a likely organizational loss for your organization, not a generic
> industry scenario.

The claim upgrades from "industry scenario" to "your organization" only when
**all five** required inputs are present — configuring just one (even
`impactUSD` alone) is not enough to earn `scenario_organization_specific`, and
is reported honestly as `scenario_partially_configured` instead.

---

## The 5 required inputs

`.agentic-security/risk-config.yml` recognizes six tunable dimensions in
total, but only five of them gate `scenario_organization_specific`
(`familyBaseProb` is a bonus calibration input, not one of the five):

| Input | Shape | What it controls |
|---|---|---|
| `impactUSD` | section, one or more of `PII`/`PHI`/`PCI`/`Confidential`/`crown-jewel`/`default`: `<dollars>` | Overrides the built-in per-data-class impact table |
| `organizationScale` | flat scalar | Organization size (free-form, e.g. an employee count) |
| `industry` | flat scalar | Industry sector (free-form, e.g. `healthcare`) |
| `recordCount` | flat scalar, integer | Records at risk — a non-numeric value is treated as not configured, never coerced to `NaN` |
| `controlStrength` | flat scalar | Qualitative control-maturity input (free-form, e.g. `medium`) |

`familyBaseProb` (optional, bonus) is a section like `impactUSD`, overriding
the built-in per-family exploit-probability table — it does not count toward
the five required inputs.

**Ordering matters in this file.** The parser is line-based: a flat scalar
key (`organizationScale`, `industry`, `recordCount`, `controlStrength`) is
only recognized while no section (`impactUSD:` / `familyBaseProb:`) is
currently open. Put the flat scalars **before** any section block — the
example below does exactly that:

```yaml
organizationScale: 1200
industry: healthcare
recordCount: 40000
controlStrength: medium
impactUSD:
  default: 500000
  PII: 300000
```

---

## Worked example: before → after

The "before" finding — a real SQL injection captured with no organization
config present — is documented field-by-field in
[Reading a finding's evidence](../walkthroughs/finding-evidence.md); its full
`riskDollars` object is reproduced above under "What ships on every finding"
rather than duplicated a second time here.

**Before** (`.agentic-security/risk-config.yml` absent):

```json
{
  "scenarioStatus": "scenario_default",
  "ev": 2066,
  "range": { "low": 620, "base": 2066, "high": 5422 }
}
```

Same finding, same reachability (`route-reachable`) and confidence (`0.255`)
— **after** configuring the five required inputs above (`impactUSD.default`
raised to $500k, plus `organizationScale`/`industry`/`recordCount`/
`controlStrength`):

```json
{
  "scenarioStatus": "scenario_organization_specific",
  "ev": 20655,
  "range": { "low": 6197, "base": 20655, "high": 54219 },
  "assumptions": [
    "probability of exploit: 0.18 (source: built-in industry base-rate table)",
    "impact estimate: $500k (tier: default, operator-configured)",
    "reachability discount: 0.9 (tier: route-reachable)",
    "confidence weight: 0.26 (measured from this scan)"
  ]
}
```

Probability, discount, and confidence weight are unchanged — only `impact`
moved (built-in $50k default → operator-configured $500k), which is why `ev`
scales roughly 10×. The `assumptions[]` entry for impact now reads
`operator-configured` instead of `built-in default`, and `scenarioStatus`
crossed from `scenario_default` to `scenario_organization_specific` because
all five required inputs are now present. `familyBaseProb` was left
unconfigured in this example, so probability still comes from the built-in
table — configuring it would not change `scenarioStatus` either way, since
it isn't one of the five gating inputs.

---

## Related

- [Reading a finding's evidence](../walkthroughs/finding-evidence.md) — every
  other field on a finding object, including where `riskDollars` sits
  relative to `exploitability`, `confidence`, and `findingProvenance`.
- [State & retention](../governance/state-and-retention.md) — `risk-config.yml`
  is `operator-config`: hand-authored, never scanner-written, never deleted
  by `reset`.
