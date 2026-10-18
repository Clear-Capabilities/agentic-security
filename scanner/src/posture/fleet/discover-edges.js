// Edges the code implies but the manifest does not declare (PRD 4: the enterprise graph should not be only what someone wrote down).
//
// What this does: reads the text of each repository's source and configuration files and looks for a few exact, checkable
// patterns that name ANOTHER node of the manifest:
//   * a URL literal whose host IS a node's id or alias, or whose first label is (payments-api matches payments-api.svc.cluster.local);
//   * a queue/topic resource's name or alias as a string literal on a line that publishes to it, or on one that consumes from it;
//   * a database resource's name or alias on a line that opens a connection.
// Each hit becomes an edge of type `calls`, `produces`, `consumes` or `connects-to` with the file and line that produced it, tagged
// `source: discovered-code-literal`, and is reported separately from declared edges: a discovered edge never replaces or hides a
// declared one, and a query result says which of its edges were only discovered.
//
// What it cannot do, and says so: it matches whole tokens, not substrings (so `orders` never matches `reorders`); it sees literals, not
// values built at run time, environment-supplied URLs or service-mesh routing; it cannot tell the direction of a database use; it
// skips comment lines but does not parse code, so a literal in a string that is never executed still counts. A discovered edge is a
// lead with evidence, not a fact. It is bounded in files, bytes and time.
import fs from 'node:fs';
import path from 'node:path';

export const DISCOVERY_LIMITS = Object.freeze({ maxFilesPerRepo: 2000, maxFileBytes: 512 * 1024, maxTotalBytes: 64 * 1024 * 1024, maxEvidencePerEdge: 3 });
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', '.venv', 'venv', '__pycache__', 'target', '.agentic-security', 'coverage', '.next', 'dist-newstyle', '.stack-work']);
const TEXT_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|py|java|kt|go|rb|php|cs|rs|scala|ya?ml|json|toml|properties|env|tf|conf|ini|hs|nix)$/i;
const COMMENT = /^\s*(?:\/\/|#|\*|\/\*|--|;)/;
const URL_RE = /\b[a-z][a-z0-9+.-]{1,12}:\/\/[^\s'"`<>)\]}]{1,300}/gi;
const PUBLISH = /\b(?:send_?message|publish|produce|send_?to_?queue|enqueue|put_?record|xadd|lpush|rpush|sendmessage|sendtoqueue|emit_?to)\b/i;
const CONSUME = /\b(?:consume|subscribe|receive_?message|poll|on_?message|get_?messages?|basic_?consume|xread|brpop|blpop|receivemessage)\b/i;
const CONNECT = /(?:\b(?:connect|create_?connection|createpool|new\s+pool|mongoclient|drivermanager|sqlalchemy|create_engine|database_url|dbname)\b|jdbc:|postgres(?:ql)?:\/\/|mysql:\/\/|mongodb(?:\+srv)?:\/\/|redis:\/\/)/i;

/** The names a node answers to: its id plus declared aliases, lower-case. */
function namesOf(node) { return [node.id, ...(node.aliases ?? [])].map((x) => String(x).toLowerCase()); }

function* sourceFiles(root, limits) {
  let count = 0; let bytes = 0;
  const stack = ['']; const rootReal = fs.realpathSync(root);
  while (stack.length) {
    const rel = stack.pop();
    let ents; try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(r); continue; }
      if (!e.isFile() || !TEXT_EXT.test(e.name)) continue;
      let st; try { st = fs.statSync(path.join(root, r)); } catch { continue; }
      if (st.size > limits.maxFileBytes) continue;
      if (++count > limits.maxFilesPerRepo || (bytes += st.size) > limits.maxTotalBytes) return;
      let real; try { real = fs.realpathSync(path.join(root, r)); } catch { continue; }
      if (!real.startsWith(rootReal + path.sep)) continue;
      yield { rel: r, abs: real };
    }
  }
}

const stringLiterals = (line) => [...line.matchAll(/(['"`])((?:\\.|(?!\1).){1,200})\1/g)].map((m) => m[2]);
const tokenIn = (haystackLiteral, name) => new RegExp(`(?:^|[^a-z0-9_-])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z0-9_-])`, 'i').test(haystackLiteral);

/**
 * @param {{manifest: object, limits?: object}} o
 * @returns {{edges: Array<{type: string, from: string, to: string, evidence: object[]}>, scanned: Record<string, {files: number, truncated: boolean}>, limitations: string[]}}
 */
export function discoverEdges({ manifest, limits = DISCOVERY_LIMITS }) {
  const L = { ...DISCOVERY_LIMITS, ...limits };
  const repoNodes = manifest.repositories.map((r) => ({ id: r.id, aliases: r.aliases ?? [], kind: 'repo' }));
  const resNodes = (manifest.resources ?? []).map((r) => ({ id: r.id, aliases: r.aliases ?? [], kind: r.kind }));
  const found = new Map(); const scanned = {};
  const add = (type, from, to, ev) => {
    const key = `${type}\u0000${from}\u0000${to}`;
    const e = found.get(key) ?? { type, from, to, evidence: [] };
    if (e.evidence.length < L.maxEvidencePerEdge) e.evidence.push({ source: 'discovered-code-literal', repo: from, declared: false, ...ev });
    found.set(key, e);
  };
  for (const repo of manifest.repositories) {
    let files = 0; let truncated = false;
    const targets = [...repoNodes.filter((n) => n.id !== repo.id), ...resNodes];
    const it = sourceFiles(repo.path, L);
    for (;;) {
      const nx = it.next();
      if (nx.done) break;
      files++;
      let text; try { text = fs.readFileSync(nx.value.abs, 'utf8'); } catch { continue; }
      if (text.includes('\0')) continue;
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000 || COMMENT.test(line)) continue;
        // 1. URL literals naming a repository or gateway
        for (const m of line.matchAll(URL_RE)) {
          let host; try { host = new URL(m[0].replace(/[.,;]+$/, '')).hostname.toLowerCase(); } catch { continue; }
          const first = host.split('.')[0];
          for (const n of targets) {
            if (n.kind !== 'repo' && n.kind !== 'gateway' && n.kind !== 'external-provider') continue;
            if (namesOf(n).some((nm) => nm === host || nm === first)) add(n.kind === 'external-provider' ? 'uses-provider' : 'calls', repo.id, n.id, { file: nx.value.rel, line: i + 1, host });
          }
          for (const n of targets) if (n.kind === 'database' && namesOf(n).some((nm) => nm === host || nm === host.split('.')[0]) && CONNECT.test(m[0])) add('connects-to', repo.id, n.id, { file: nx.value.rel, line: i + 1, host });
        }
        // 2. queue and database names as literals on a publishing / consuming / connecting line
        const lits = stringLiterals(line);
        if (!lits.length) continue;
        for (const n of targets) {
          if (n.kind === 'queue') {
            if (!lits.some((l) => namesOf(n).some((nm) => tokenIn(l, nm)))) continue;
            if (PUBLISH.test(line)) add('produces', repo.id, n.id, { file: nx.value.rel, line: i + 1, name: n.id });
            else if (CONSUME.test(line)) add('consumes', n.id, repo.id, { file: nx.value.rel, line: i + 1, name: n.id });
          } else if (n.kind === 'database' && CONNECT.test(line) && lits.some((l) => namesOf(n).some((nm) => tokenIn(l, nm)))) add('connects-to', repo.id, n.id, { file: nx.value.rel, line: i + 1, name: n.id });
        }
      }
    }
    if (files >= L.maxFilesPerRepo) truncated = true;
    scanned[repo.id] = { files, truncated };
  }
  return {
    edges: [...found.values()].sort((a, b) => (a.type + a.from + a.to < b.type + b.from + b.to ? -1 : 1)),
    scanned,
    limitations: [
      'Only string and URL literals are seen: a URL built at run time, read from the environment or routed by a mesh is not found.',
      'Names match as whole tokens; an alias must be declared in the manifest for a node whose code name differs from its id.',
      'The direction of a database use is not known, so those edges are `connects-to`.',
      'A discovered edge is a lead with file and line evidence, not a confirmed call.',
    ],
  };
}

/** Discovered edges whose (type, from, to) the manifest already declares, and those it does not. */
export function splitDeclared(discovered, manifest) {
  const declared = new Set();
  for (const r of manifest.repositories) {
    for (const t of r.calls) declared.add(`calls\u0000${r.id}\u0000${t}`);
    for (const t of r.produces) declared.add(`produces\u0000${r.id}\u0000${t}`);
    for (const t of r.consumes) declared.add(`consumes\u0000${t}\u0000${r.id}`);
    for (const t of r.providers) declared.add(`uses-provider\u0000${r.id}\u0000${t}`);
    for (const t of [...r.reads, ...r.writes]) declared.add(`connects-to\u0000${r.id}\u0000${t}`);
  }
  const undeclared = []; const confirmed = [];
  for (const e of discovered.edges) (declared.has(`${e.type}\u0000${e.from}\u0000${e.to}`) ? confirmed : undeclared).push(e);
  return { undeclared, confirmed };
}
