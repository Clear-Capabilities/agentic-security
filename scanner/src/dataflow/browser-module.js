// A JavaScript or TypeScript module that runs in the browser.
//
// A `"use client"` component, a React hook file, a page's client-side API wrapper: the code issues same-origin or CORS-bound requests
// from the user's own browser, has no file system and no shell, and a regular expression it compiles can only stall that user's own
// tab. A server-side request forgery, a path traversal, a file write, a command injection or a regular-expression denial of service
// reported in such a module describes a server that is not there. Cross-site scripting and client-side redirects stay: the browser is
// exactly where those happen.
//
// The decision reads the module's own text, never its path or its name: the `"use client"` directive at the head, or an import of a
// client-side UI library TOGETHER with a use of a browser-only API or hook (a React server component imports `react` too, and its
// `fetch` runs on the server, so the import alone decides nothing). Any import of a Node built-in, a server framework or a database
// client makes the module server-side whatever else it imports.

const CLIENT_LIB_RE = /^(?:react|react-dom(?:\/.*)?|next\/(?:navigation|link|image|router|dynamic)|vue|svelte(?:\/.*)?|@angular\/(?:core|common)|preact(?:\/.*)?|solid-js|@tanstack\/react-query|swr|@apollo\/client)$/;
const SERVER_MODULE_RE = /^(?:node:.*|fs|fs\/promises|child_process|net|http|https|http2|os|cluster|dgram|tls|worker_threads|zlib|stream|readline|vm|express|fastify|koa|hono|@hono\/.*|next\/server|next\/headers|@nestjs\/.*|@trpc\/server(?:\/.*)?|@remix-run\/node|@sveltejs\/kit(?:\/.*)?|pg|mysql2?|knex|typeorm|@prisma\/client|mongoose|ioredis|redis|@aws-sdk\/.*|server-only)$/;
const CLIENT_API_RE = /\b(?:window|document|navigator|localStorage|sessionStorage|useState|useEffect|useLayoutEffect|useMemo|useCallback|useRef|useReducer|useContext|useSearchParams|useRouter|usePathname|useQuery|useMutation|useSWR|defineComponent|onMount|createSignal)\b/;
const DIRECTIVE_RE = /^(?:\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*\s*(['"])use client\1\s*;?/;
const IMPORT_RE = /\b(?:import\s*(?:type\s+)?(?:[\w$*{}\s,]+?\s*from\s*)?|require\s*\(\s*|import\s*\(\s*)(['"])([^'"\n]+)\1/g;
const HEAD_CHARS = 64 * 1024;

/** Does this module's text say it runs in the browser? Never true for text that imports a Node built-in or a server framework. */
export function isBrowserModule(text) {
  if (typeof text !== 'string' || !text) return false;
  const head = text.slice(0, HEAD_CHARS);
  const specs = [];
  let m;
  const re = new RegExp(IMPORT_RE.source, IMPORT_RE.flags);
  while ((m = re.exec(head))) specs.push(m[2]);
  if (specs.some((s) => SERVER_MODULE_RE.test(s))) return false;
  if (DIRECTIVE_RE.test(head)) return true;
  return specs.some((s) => CLIENT_LIB_RE.test(s)) && CLIENT_API_RE.test(head);
}

/** The weakness classes that need a server to exist. */
const SERVER_ONLY_CWES = new Set(['CWE-918', 'CWE-22', 'CWE-73', 'CWE-78', 'CWE-1333']);

const JS_FILE_RE = /\.(?:[cm]?jsx?|tsx?)$/i;

/**
 * Drop the server-only findings that sit in a browser module. The finding's own file decides; a cross-file finding written
 * `caller -> callee` is dropped when either file is a browser module: a chain that starts in a client component runs in the browser
 * whatever the helper it calls looks like, and a helper that is itself a client module runs there too. `onDrop(finding, { kind, file })`
 * records each drop so it can be ledgered.
 */
export function dropBrowserModuleServerFindings(findings, fileContents, onDrop = null) {
  if (!Array.isArray(findings) || !fileContents) return findings;
  const cache = new Map();
  const browser = (file) => {
    if (cache.has(file)) return cache.get(file);
    const v = JS_FILE_RE.test(file) && isBrowserModule(fileContents[file]);
    cache.set(file, v);
    return v;
  };
  return findings.filter((f) => {
    if (!f || !f.file || !SERVER_ONLY_CWES.has(f.cwe)) return true;
    const file = String(f.file).split(' -> ').find(browser);
    if (!file) return true;
    if (onDrop) onDrop(f, { kind: 'browser-module', file });
    return false;
  });
}
