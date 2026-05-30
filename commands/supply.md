---
description: Supply chain. SCA + SBOM + CVE alerts + license analysis in one command.
argument-hint: "[--check|--sbom|--cve-alerts|--license]"
---

# /supply

Supply chain dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| (default) or `--check` | Full SCA pass: OSV + KEV + EPSS, function-level reachability, dependency confusion |
| `--sbom` | Conversational SBOM exploration — query deps, drift, transitive paths in natural language |
| `--cve-alerts` | Subscribe to a daemon that pings when a new CVE affects an installed dep |
| `--license` | License-graph view: per-component license, transitive copyleft, dual-license traps. Backed by `license-graph.js`. |

## Examples

```bash
/supply                                          # SCA check (default)
/supply --sbom "show me every transitive added this month"
/supply --cve-alerts --setup                     # configure the daemon
/supply --license --distribution-mode saas       # license-graph in SaaS mode
```

## Implementation

Routes to existing modules: SCA engine (built-in), `posture/sbom-diff.js`, `posture/cve-alert-daemon`, `posture/license-graph.js`.
