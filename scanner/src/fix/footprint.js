// Functional footprint of a patch (E3-05): did the patch fix the weakness, or remove the feature?
//
// A rescan only proves the finding stopped firing. A patch that deletes the vulnerable behaviour (a blanket 403 on an IDOR route, a 501 on
// the SQL endpoint, an emptied file) satisfies that just as well, so it is checked separately: the kinds of sensitive operation the
// changed files performed BEFORE the patch must still be performed AFTER it. A parameterised query is still a database read; an
// execFile call is still a process execution; a deny-all handler is neither.
//
// This is a HEURISTIC over source text, not a proof of equivalence. It catches the removal of a whole operation kind, not a subtler
// behaviour change. When it cannot see any operation kind in the original it says `unobservable` and the leg is not_run, never passed.
const KINDS = {
  'process-exec': /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|\b(?:execSync|execFileSync|execFile|spawnSync|spawn|exec|system|popen|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder|subprocess\s*\.\s*\w+|os\s*\.\s*system|shell_exec|passthru|proc_open)\s*\(/,
  'data-access': /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b|\.(?:find|findOne|findById|findAll|findUnique|findFirst|query|execute|executeQuery|executemany|prepare|raw|where|get_object_or_404|createQuery|queryForObject)\s*\(|\b(?:db|database|conn|connection|pool|cursor|collection|repository|repo|prisma|knex|sequelize|session)\w*\s*\.\s*\w+\s*\(/i,
  'file-access': /\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|sendFile|readdir|readdirSync|unlink|open|os\.Open|ioutil\.ReadFile|file_get_contents|File\s*\(|FileInputStream|FileReader|Files\s*\.\s*\w+)\s*\(/,
  'network-out': /\b(?:fetch|axios|got|request|urlopen|requests\s*\.\s*\w+|http\s*\.\s*(?:get|request)|https\s*\.\s*(?:get|request)|HttpClient|http\.Get|curl_exec)\s*\(/,
  'html-output': /\b(?:res|response|reply|ctx)\b[^;\n]*\.\s*(?:send|write|render|json|end)\s*\(|\b(?:render_template|HttpResponse|JsonResponse|jsonify|innerHTML|echo|ResponseEntity|c\.JSON|c\.String)\b/,
};
const DENIAL = /\b(?:status\s*\(\s*(?:401|403|404|405|410|501|503)\s*\)|(?:abort|HTTPException|http_error|ResponseStatusException)\s*\(\s*(?:401|403|404|501)|(?:PermissionDenied|Forbidden|NotImplemented|AccessDenied|Unauthorized)\b|(?:forbidden|not implemented|access denied|disabled)\b|return\s+(?:403|401|501)\b|StatusForbidden|StatusNotImplemented)/i;
// Which kinds a CWE's fix must keep. Unlisted weaknesses are held to every kind the original had.
const CWE_KINDS = {
  'CWE-78': ['process-exec'], 'CWE-77': ['process-exec'], 'CWE-89': ['data-access'], 'CWE-564': ['data-access'], 'CWE-22': ['file-access'], 'CWE-73': ['file-access'],
  'CWE-918': ['network-out'], 'CWE-79': ['html-output'], 'CWE-639': ['data-access'], 'CWE-284': ['data-access'], 'CWE-285': ['data-access'], 'CWE-862': ['data-access'], 'CWE-863': ['data-access'], 'CWE-566': ['data-access'],
};

const stripComments = (t) => String(t || '').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:\\])\/\/[^\n]*/g, '$1').replace(/(^|\s)#[^\n!][^\n]*/g, '$1');
const codeLines = (t) => stripComments(t).split('\n').filter((l) => l.trim() && !/^\s*[{}();,]*\s*$/.test(l)).length;

export function kindsOf(text) {
  const src = stripComments(text);
  return Object.entries(KINDS).filter(([, re]) => re.test(src)).map(([k]) => k).sort();
}

/**
 * @param {{before:Record<string,string|null>, after:Record<string,string>, cwe?:string|null, intentionalRemoval?:{reason:string}|null}} o
 * @returns {{status:'passed'|'failed'|'not_run', reason:string|null, files:object[], lost:string[]}}
 */
export function checkFootprint({ before, after, cwe = null, intentionalRemoval = null }) {
  const required = CWE_KINDS[String(cwe || '').toUpperCase()] || null;
  const files = [];
  const lostAll = new Set();
  let observed = false;
  for (const [rel, afterText] of Object.entries(after)) {
    const b = before[rel];
    if (b === null || b === undefined) { files.push({ file: rel, note: 'new file' }); continue; }
    const kb = kindsOf(b); const ka = kindsOf(afterText);
    const held = required ? kb.filter((k) => required.includes(k)) : kb;
    if (held.length) observed = true;
    let lost = held.filter((k) => !ka.includes(k));
    const emptied = codeLines(afterText) === 0 && codeLines(b) > 0;
    const denialOnly = lost.length > 0 && DENIAL.test(stripComments(afterText)) && !DENIAL.test(stripComments(b));
    // With no known weakness class, losing an operation kind is not by itself a defect (an auth fix may legitimately drop a response path).
    // What marks feature REMOVAL is the signature of it: the file emptied, or the lost operation replaced by a deny response.
    if (!required && !emptied && !denialOnly) lost = [];
    const shrunk = codeLines(b) >= 6 && codeLines(afterText) <= Math.floor(codeLines(b) * 0.25);
    files.push({ file: rel, kindsBefore: kb, kindsAfter: ka, lost, emptied, denialOnly, shrunk });
    if (emptied) { lost.push('everything'); observed = true; }
    for (const k of lost) lostAll.add(k);
  }
  if (!observed && ![...lostAll].length) return { status: 'not_run', reason: 'unobservable: no sensitive operation was recognised in the original files, so removal of the feature cannot be judged', files, lost: [] };
  if (lostAll.size) {
    if (intentionalRemoval && typeof intentionalRemoval.reason === 'string' && intentionalRemoval.reason.trim()) return { status: 'not_run', reason: `the patch removes ${[...lostAll].join(', ')} and the caller declared that intentional (${intentionalRemoval.reason.trim().slice(0, 200)}); a person must confirm it`, files, lost: [...lostAll] };
    const why = files.filter((f) => f.lost?.length).map((f) => `${f.file}: no longer performs ${f.lost.join(', ')}${f.denialOnly ? ' (replaced by a deny response)' : ''}${f.emptied ? ' (file emptied)' : ''}`).join('; ');
    return { status: 'failed', reason: `the patch removes functionality instead of fixing it: ${why}`, files, lost: [...lostAll] };
  }
  return { status: 'passed', reason: null, files, lost: [] };
}
