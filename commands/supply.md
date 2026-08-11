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
| `--cve-alerts` | One-shot check now for new CVEs against installed deps, plus help scheduling recurring checks |
| `--license` | License-graph view: per-component license, transitive copyleft, dual-license traps. Backed by `license-graph.js`. |

Add `--json` to any mode for machine-readable output.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
FLAG="--check"
PATH_ARG="."
JSON=""
for arg in "$@"; do
  case "$arg" in
    --check|--sbom|--cve-alerts|--license) FLAG="$arg" ;;
    --json) JSON="--format json" ;;
    *) PATH_ARG="$arg" ;;
  esac
done

case "$FLAG" in
  --check)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --only sca ${JSON:---format cli}
    ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec ;;
  --sbom|--license)
    if [ ! -f "$PATH_ARG/.agentic-security/last-scan.json" ]; then
      echo "No prior scan found. Running one now (this also computes the SBOM diff / license graph)..."
      node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" --format json > /dev/null
    fi
    node -e "
      const fs = require('fs');
      const path = require('path');
      const scan = JSON.parse(fs.readFileSync(path.join('$PATH_ARG', '.agentic-security', 'last-scan.json'), 'utf8'));
      const key = '$FLAG' === '--sbom' ? 'sbomDiff' : 'licenseGraph';
      const data = scan[key];
      if (!data) { console.log(JSON.stringify({ error: key + ' was not computed on the last scan (no components found)' })); process.exit(0); }
      console.log(JSON.stringify({ [key]: data, components: scan.components || [] }, null, 2));
    "
    ;;
  --cve-alerts)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs cve-watch --root "$PATH_ARG" --dry-run --json
    ;;
esac
```

### `--sbom` — after the block runs

The `sbomDiff` object is `{ findings, summary: {added, removed, bumped, substituted}, first }` — `first: true` means this is the first scan ever (no prior snapshot to diff against, so nothing to report yet). `components` is the full current SBOM. Answer the user's questions about dependencies, drift, and transitive paths conversationally from this data — don't just dump the JSON.

### `--license` — after the block runs

The `licenseGraph` object is `{ findings, summary: {total, deny, review, allow, unknown}, distributionMode }` — `findings` are the actual violations (copyleft-in-SaaS, dual-license traps, denied licenses per `.agentic-security/license-policy.yml` if one exists); `summary` is the per-component breakdown. Walk the user through any `deny`/`review` entries first, then offer the full per-component table if they want it.

### `--cve-alerts` — after the block runs

This is a **one-shot check**, not a persistent subscription — nothing in this session can stay running after the conversation ends. Report `newAdvisories` from the JSON output now. Then, if the user wants ongoing monitoring, offer to help them wire `agentic-security cve-watch` into a scheduled GitHub Actions workflow (cron trigger) or their existing CI cron, the same way `/setup --ci` generates a workflow file — this command does not do that generation itself.

## After `--check`: offer the safe-upgrade PR

When `--check` finishes, partition the vulnerable dependencies into:

- **Safe** — a patch- or minor-level bump exists that clears the advisory with no major-version jump (low regression risk).
- **Risky** — only a major-version bump fixes it, or no fix is published yet.

Bundle the **safe** set and offer to open one PR via `/fix --sca --pr`: a single branch + commit that bumps every safe dependency at once, with a summarized changelog and the cleared advisory IDs in the PR body. List the **risky** set separately for manual review — never auto-bump across a major version.

## Implementation

`--check` routes to the built-in SCA engine via the real `scan --only sca` CLI invocation above. `--sbom` and `--license` read `scan.sbomDiff` / `scan.licenseGraph` (`posture/sbom-diff.js` / `posture/license-graph.js`) from `.agentic-security/last-scan.json`, running a scan first if none exists. `--cve-alerts` runs the real `cve-watch` CLI subcommand (`posture/cve-alert-daemon.js`) as a one-shot check.
