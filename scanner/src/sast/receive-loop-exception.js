// C#: one malformed message ends a network receive loop (CWE-248).
//
// A server's receive loop (`while (_running) { ... ReceiveAsync ... }`) hands
// each datagram or frame to a parser or handler. Parsers throw on input they
// do not recognise. When the handler call is not wrapped in a try INSIDE the
// loop body, the exception unwinds past the loop: either to a catch outside it
// (which logs and returns, so the loop is over) or out of the task entirely.
// One packet from anyone who can reach the port stops the service for every
// client until the process restarts.
//
// Fires on a call to a Handle* / Process* / Parse* / Dispatch* / On* method
// that follows a receive or read call in the same loop body and is not inside
// a try block opened within that loop. Silent when the call is wrapped, when
// the loop has no receive or read call, and for fire-and-forget dispatch
// (`_ = HandleAsync(...)`, `Task.Run(...)`), whose exceptions do not reach the
// loop. Reported at the handler call, where the try belongs.

const TEST_PATH = /(?:^|[\\/])(?:test|tests|spec|__tests__|fixtures?)[\\/]|Tests?\.cs$/i;
const RECEIVE = /\.\s*(?:Receive(?:From|Message)?(?:Async)?|Read(?:Exact)?Async|ReadExact|ReadFrom(?:Async)?)\s*\(|\bReadExactAsync\s*\(/;
const HANDLER = /^\s*(?:(?:var|[\w<>[\],]+)\s+\w+\s*=\s*|\w+\s*=\s*)?(?:await\s+)?(?:[A-Z]\w*\.)?((?:Handle|Process|Parse|Dispatch|On)[A-Z]\w*)\s*\(/;

/** For each line from `from` to `to`, is it inside a try block opened at or after `from`? */
function tryDepthMap(lines, from, to) {
  const inTry = new Array(to - from + 1).fill(false);
  const stack = []; // 'try' | 'other'
  let pendingTry = false;
  for (let k = from; k <= to; k++) {
    const l = lines[k];
    inTry[k - from] = stack.includes('try');
    // Strip string literals so braces inside them do not count.
    const t = l.replace(/@?"(?:[^"\\\n]|\\.)*"/g, '""').replace(/'(?:[^'\\\n]|\\.)'/g, "''");
    for (let i = 0; i < t.length; i++) {
      if (/\btry\b/.test(t.slice(i, i + 3)) && (i === 0 || !/\w/.test(t[i - 1])) && !/\w/.test(t[i + 3] || '')) { pendingTry = true; i += 2; continue; }
      const c = t[i];
      if (c === '{') { stack.push(pendingTry ? 'try' : 'other'); pendingTry = false; } else if (c === '}') stack.pop();
      else if (c === ';') pendingTry = false;
    }
    if (stack.includes('try')) inTry[k - from] = true;
  }
  return inTry;
}

function blockRange(lines, i) {
  let depth = 0; let opened = false;
  for (let k = i; k < lines.length && k < i + 400; k++) {
    for (const c of lines[k]) {
      if (c === '{') { depth++; opened = true; } else if (c === '}') { depth--; if (opened && depth === 0) return [i, k]; }
    }
  }
  return null;
}

export function scanReceiveLoopException(file, code) {
  if (typeof code !== 'string' || !code) return [];
  const f = String(file || '');
  if (!/\.cs$/i.test(f) || TEST_PATH.test(f)) return [];
  if (!RECEIVE.test(code)) return [];
  const lines = code.split('\n');
  const out = [];
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*while\s*\(/.test(lines[i])) continue;
    const r = blockRange(lines, i);
    if (!r) continue;
    const [s, e] = r;
    const recv = lines.slice(s, e + 1).findIndex((l) => RECEIVE.test(l));
    if (recv < 0) continue;
    const inTry = tryDepthMap(lines, s + 1, e);
    for (let k = s + recv + 1; k < e; k++) {
      const m = lines[k].match(HANDLER);
      if (!m || inTry[k - (s + 1)] || seen.has(k)) continue;
      // A nested loop is judged on its own.
      seen.add(k);
      out.push({
        id: `receive-loop-exception:${f}:${k + 1}`,
        file: f, line: k + 1,
        vuln: 'Unhandled exception from one message ends the receive loop',
        severity: 'medium',
        cwe: 'CWE-248',
        family: 'resource-exhaustion',
        stride: 'Denial of Service',
        description: `\`${m[1]}\` processes a message received in the loop that starts at line ${i + 1}, and nothing inside the loop catches what it throws. A malformed message from the network unwinds past the loop, so a single packet stops the receive path for every client until the process restarts.`,
        remediation: 'Wrap the per-message parse and handling in a try/catch inside the loop body, log and drop the message, and keep receiving. Leave socket and cancellation exceptions to the outer handler so a closed socket still ends the loop.',
        snippet: lines[k].trim().slice(0, 200),
        parser: 'CS-RECEIVE-LOOP',
        confidence: 0.45,
      });
    }
    i = e;
  }
  return out;
}
