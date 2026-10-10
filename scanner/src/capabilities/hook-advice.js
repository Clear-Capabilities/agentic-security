// What a hook says about a tool use (X-505.AC01).
//
// The pre-edit, pre-bash and dispatch hooks, and the MCP tool gate, ask the SAME
// function (`decide`) the runner asks. A hook's answer is advice: the record is
// `hook-advisory`, `enforced` is always false, and a hook never blocks on it. The
// runner is what stops a task; a hook only explains why it would.
//
// Tool names here are the names the HOST agent uses (`mcp__<server>__<tool>`,
// `Task`, `Edit` ...), compared exactly. The MCP server's own gate sees the short
// tool names. A manifest declares the spelling it means; there is no aliasing, so
// `mcp__other__apply_fix` is not `apply_fix`.
import { advise } from './records.js';

const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
const DELEGATE_TOOLS = new Set(['Task', 'Agent']);

/** The capability action a host tool use amounts to, or null when this layer has no opinion. */
export function actionForToolUse(evt) {
  const tool = evt && (evt.tool_name || evt.toolName);
  const input = (evt && evt.tool_input) || {};
  if (typeof tool !== 'string') return null;
  if (EDIT_TOOLS.has(tool)) {
    const p = input.file_path ?? input.notebook_path;
    return { kind: 'filesystem-write', path: typeof p === 'string' ? p : undefined };
  }
  if (tool === 'Bash') return { kind: 'command', command: typeof input.command === 'string' ? input.command : '' };
  if (DELEGATE_TOOLS.has(tool)) return { kind: 'delegation', depth: 0 };
  if (tool.startsWith('mcp__')) return { kind: 'tool', tool };
  return null;
}

/**
 * @param {{manifest:object,binding:object}} bound
 * @param {object} evt   a PreToolUse event
 * @param {{binding: object}} ctx  the identity the session claims
 * @returns {{advisory:true, enforced:false, decision:string, code:string, lines:string[], record:object|null}|null}
 */
export function adviseToolUse(bound, evt, ctx) {
  const action = actionForToolUse(evt);
  if (!action) return null;
  const a = advise(bound, action, ctx);
  const tool = String(evt.tool_name || evt.toolName);
  const lines = [];
  if (a.decision !== 'allow') {
    lines.push(`agentic-security capability advisory (not enforced): ${tool} -> ${a.decision} (${a.code})`);
    lines.push(`  ${a.note}`);
    if (action.kind === 'delegation') lines.push('  a delegated agent can only receive a subset of this task\'s capabilities (capabilities/delegate.js)');
  }
  return Object.freeze({ advisory: true, enforced: false, decision: a.decision, code: a.code, lines, record: a.record });
}
