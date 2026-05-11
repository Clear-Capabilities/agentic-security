---
description: Posture management — SBOM, AI-BOM, API inventory, license policy, drift analysis, and SLA tracking. Use --sbom, --aibom, --api, --license, --drift, or --mttr.
argument-hint: "[--sbom [--format cyclonedx|spdx] [--output <file>]] | [--aibom [--format aibom|aibom-md] [--output <file>]] | [--api [--format md|json|openapi] [--output <file>]] | [--license [--init]] | [--drift [--from <scan-a.json>] [--to <scan-b.json>]] | [--mttr [--sla-days '{\"critical\":7,\"high\":30}']]"
---

Run posture management commands against the current project.

```bash
FLAG=""
FORMAT=""
OUTPUT=""
FROM=".agentic-security/last-scan.json"
TO=".agentic-security/last-scan.json"
SLA_DAYS=""
INIT=false

i=1
for arg in "$@"; do
  case "$arg" in
    --sbom|--aibom|--api|--license|--drift|--mttr) FLAG="$arg" ;;
    --init) INIT=true ;;
    --from) NEXT_IS_FROM=1 ;;
    --to)   NEXT_IS_TO=1 ;;
    --format) NEXT_IS_FORMAT=1 ;;
    --output) NEXT_IS_OUTPUT=1 ;;
    --sla-days) NEXT_IS_SLA=1 ;;
    *)
      [ -n "$NEXT_IS_FROM" ]   && FROM="$arg"   && unset NEXT_IS_FROM ||
      [ -n "$NEXT_IS_TO" ]     && TO="$arg"     && unset NEXT_IS_TO   ||
      [ -n "$NEXT_IS_FORMAT" ] && FORMAT="$arg" && unset NEXT_IS_FORMAT ||
      [ -n "$NEXT_IS_OUTPUT" ] && OUTPUT="$arg" && unset NEXT_IS_OUTPUT ||
      [ -n "$NEXT_IS_SLA" ]    && SLA_DAYS="$arg" && unset NEXT_IS_SLA
      ;;
  esac
done

case "$FLAG" in
  --sbom)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . \
      --format ${FORMAT:-cyclonedx} \
      --output ${OUTPUT:-sbom.json}
    ;;
  --aibom)
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . \
      --format ${FORMAT:-aibom-md} \
      --output ${OUTPUT:-aibom.md}
    ;;
  --api)
node -e "
const { runScan } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/runScan.js');
const { toAPIInventoryMarkdown, toAPIInventoryJSON, toOpenAPI } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/api-inventory.js');
const { scan, meta } = await runScan('.');
const fmt = '${FORMAT:-md}';
let body;
if (fmt === 'json') body = JSON.stringify(toAPIInventoryJSON(scan), null, 2);
else if (fmt === 'openapi') body = JSON.stringify(toOpenAPI(scan, meta), null, 2);
else body = toAPIInventoryMarkdown(scan);
process.stdout.write(body);
"
    ;;
  --license)
    if [ "$INIT" = "true" ] || [ ! -f ".agentic-security/license-policy.yml" ]; then
      mkdir -p .agentic-security
      cat > .agentic-security/license-policy.yml << 'POLICYEOF'
allow:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - 0BSD
  - Unlicense
deny:
  - GPL-3.0
  - GPL-2.0
  - AGPL-3.0
  - AGPL-1.0
  - SSPL-1.0
review:
  - LGPL-2.1
  - LGPL-3.0
  - MPL-2.0
  - EPL-2.0
unknown: review
POLICYEOF
      echo "Created .agentic-security/license-policy.yml — edit to match your org policy."
    fi
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format cli
    ;;
  --drift)
node -e "
const { driftBetween, driftToMarkdown } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/drift.js');
const fs = await import('node:fs/promises');
const a = JSON.parse(await fs.readFile('${FROM}', 'utf8'));
const b = JSON.parse(await fs.readFile('${TO}', 'utf8'));
process.stdout.write(driftToMarkdown(driftBetween(a, b)));
"
    ;;
  --mttr)
node -e "
const fs = await import('node:fs/promises');
const { findingsExceedingSLA } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/mttr.js');
const current = JSON.parse(await fs.readFile('.agentic-security/last-scan.json', 'utf8'));
const findings = [...(current.findings||[]), ...(current.secrets||[]), ...(current.supplyChain||[]).filter(s => s.type==='vulnerable_dep')];
const overSla = findingsExceedingSLA(findings);
console.log('SLA breaches:', overSla.length);
for (const f of overSla.slice(0, 20)) console.log('  ' + f.severity + '\t' + f.ageDays + 'd\t' + (f.file||'') + ':' + (f.line||0) + '\t' + (f.vuln||''));
"
    ;;
  *)
    echo "Usage: /posture-management <mode> [options]"
    echo ""
    echo "  --sbom    [--format cyclonedx|spdx] [--output <file>]"
    echo "            CycloneDX 1.6 or SPDX 2.3 software bill of materials"
    echo ""
    echo "  --aibom   [--format aibom|aibom-md] [--output <file>]"
    echo "            AI/ML Bill of Materials — models, prompts, frameworks, vector stores"
    echo ""
    echo "  --api     [--format md|json|openapi] [--output <file>]"
    echo "            Full API surface map annotated with auth status and data classes"
    echo ""
    echo "  --license [--init]"
    echo "            Enforce license allow/deny/review policy on all dependencies"
    echo ""
    echo "  --drift   [--from <scan-a.json>] [--to <scan-b.json>]"
    echo "            Compare two scan snapshots — new findings, lost auth, new deps"
    echo ""
    echo "  --mttr    [--sla-days '{\"critical\":7,\"high\":30,\"medium\":60,\"low\":90}']"
    echo "            Show findings exceeding per-severity SLA thresholds"
    exit 1
    ;;
esac
```

## Modes

**`/posture-management --sbom`** — Emit a CycloneDX 1.6 or SPDX 2.3 SBOM. Every component includes `purl`, license, scope, CVE IDs, CVSS vectors, EPSS scores, and `agentic-security:functionReachable` annotations. Required for FedRAMP, EU CRA, NIST SSDF, EO 14028, and most SOC 2 audits.

**`/posture-management --aibom`** — AI/ML Bill of Materials (CycloneDX 1.7 ML-BOM compatible). Captures every model, prompt template, inference framework, and vector store. Required by EU AI Act and enterprise security questionnaires.

**`/posture-management --api`** — Export the full API surface from the last scan. Each endpoint is annotated with auth status (🔒 / ⚠️) and data classifications (PII / PHI / PCI / Confidential). Available formats: `md` (risk-sorted table), `json` (machine-readable), `openapi` (OpenAPI 3.1 stub with security schemes).

**`/posture-management --license [--init]`** — Enforce a license allow/deny/review policy on the dependency tree. Use `--init` to create a default policy at `.agentic-security/license-policy.yml`. Violations appear as `kind: 'license'` findings: `high` for denied licenses (e.g., GPL-3.0 in closed-source), `low` for review-required or missing.

**`/posture-management --drift`** — Diff two scan JSON snapshots. Reports: auth boundaries lost, new endpoints, new CVEs, severity deltas, newly exposed data classes. Defaults `--from` to the previous scan and `--to` to the current `.agentic-security/last-scan.json`. Follow-ups: `critical` → `/exploit-poc` + `/fix --one`; `high` → `/show-findings --chains`.

**`/posture-management --mttr`** — Show findings breaching per-severity SLA thresholds (default: critical=7d, high=30d, medium=60d, low=90d). Finding age is measured from the scan timestamp in `last-scan.json`.

🛡  agentic-security · created by ClearCapabilities.Com
