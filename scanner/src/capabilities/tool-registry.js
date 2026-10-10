// The capability classification of every registered MCP tool (X-505.AC01).
//
// A tool that writes, runs a project command or reaches the network must say so,
// and the gate (tool-gate.js) checks what it declares before the handler runs. A
// tool that is not in this table is refused when the gate is active
// (`tool-unclassified`), so adding a tool to the MCP registry without classifying
// it fails closed and fails a test (test/capabilities/tools.test.js compares this
// table with the registry in both directions).
//
//   effect    'read'      reads local state only
//             'mutating'  writes project or agent state, or runs project code
//             'external'  reaches, or may reach, the network through a package
//                         manager or another tool the server process runs
//   requires  the capability checks made before the handler:
//               'tool'               the tool is a declared tool action
//               'write:sessionRoot'  the session root is inside a declared write root
//
// What this table does NOT do: it does not route a tool's own file or network
// activity through the capability runner. A tool runs in the MCP server process;
// the decision is made at the tool boundary, so it is policy (`in-process-policy`),
// never enforced isolation, and the report says so.
const read = (note) => Object.freeze({ effect: 'read', requires: Object.freeze(['tool']), note });
const mutating = (note, extra = []) => Object.freeze({ effect: 'mutating', requires: Object.freeze(['tool', 'write:sessionRoot', ...extra]), note });
const external = (note, extra = []) => Object.freeze({ effect: 'external', requires: Object.freeze(['tool', ...extra]), note });

export const TOOL_CAPABILITIES = Object.freeze({
  scan_diff: read('scans files in memory'),
  query_taint: read('reads the last verified scan'),
  explain_finding: read('reads the last verified scan'),
  find_rule_module: read('reads scanner source names'),
  read_scratchpad: read('reads the agent scratchpad'),
  read_agents_memory: read('reads the continual-learning file'),
  lookup_cve: read('reads the local advisory caches'),
  query_triage_memory: read('reads past triage decisions'),
  query_findings_memory: read('reads accumulated scan memory'),
  query_cache_telemetry: read('reads the session transcript statistics'),
  synthesize_fix: read('returns a stored patch'),
  dataflow_get_graph: read('reads the signed graph artifact'),
  dataflow_get_node: read('reads the signed graph artifact'),
  dataflow_get_edge: read('reads the signed graph artifact'),
  dataflow_get_flow: read('reads the signed graph artifact'),
  invariant_scenario_export: read('builds a read-only scenario export from a supplied contract, confined to the session root'),
  portfolio_progress: read('builds a read-only progress view from a portfolio store, ledger and optional inputs, confined to the session root'),
  apply_fix: mutating('writes verified patches into the project'),
  verify_fix: mutating('runs the project linter and tests and appends fix metrics'),
  append_scratchpad: mutating('writes under the agent scratchpad'),
  append_agents_memory: mutating('appends to the continual-learning file'),
  synthesize_sca_upgrade: external('runs a package manager dry-run, which may reach a registry'),
  apply_sca_upgrade: external('runs the package manager and the project tests and rewrites manifests', ['write:sessionRoot']),
});

export function toolCapabilityFor(name) {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(TOOL_CAPABILITIES, name) ? TOOL_CAPABILITIES[name] : null;
}

/** Tools whose effect is not read-only: the ones that must always be checked. */
export function isMutatingOrExternal(name) {
  const c = toolCapabilityFor(name);
  return c ? c.effect !== 'read' : true; // an unclassified tool is treated as the riskiest
}
