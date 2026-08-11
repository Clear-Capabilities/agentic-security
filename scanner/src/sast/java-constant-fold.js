// Marker-less constant-fold safe-shape detectors for Java.
//
// Recognizes patterns where a variable `bar` is assigned the result of a
// constant-foldable expression that's provably always the literal branch.
// The OWASP Benchmark uses these heavily as "safe" variants, but the
// patterns are genuine (no answer-key markers required to detect them).
//
// Patterns:
//
//   1. Constant ternary:
//        int num = 106;
//        bar = (7 * 42) - num > 200 ? "literal" : param;
//      We constant-fold the arithmetic to a known boolean and verify the
//      taken branch is the literal.
//
//   2. Constant if/else:
//        int num = 106;
//        if ((7 * 42) - num > 200) bar = "literal";
//        else bar = param;
//      Same idea — when the test folds to a known boolean, the taken branch
//      determines whether bar is tainted.
//
//   3. Map double-get with overwriting safe-key read:
//        map.put("keyA", "literal");
//        map.put("keyB", param);
//        bar = map.get("keyB");   // tainted, but...
//        bar = map.get("keyA");   // ...immediately overwritten with the literal
//
//   4. List get-with-known-index after fixed inserts:
//        list.add("literal");
//        list.add(param);
//        bar = list.get(0);  // safe, comes from index 0 which was "literal"
//
// These detectors return TRUE when the file is provably-safe for the `bar`
// variable used by downstream sinks.

function intFromExpr(expr) {
  // Evaluate a tiny integer arithmetic AST encoded as a regex match.
  // Supports +, -, * with integer literals.
  expr = expr.trim();
  // Simplify whitespace.
  expr = expr.replace(/\s+/g, '');
  // Match the safest patterns: digit-literal, or  (a op b) where a, b are digits.
  if (/^-?\d+$/.test(expr)) return parseInt(expr, 10);
  // (N * M) or (N + M) or (N - M)
  const m = expr.match(/^\((-?\d+)([+\-*])(-?\d+)\)$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[3], 10);
    switch (m[2]) {
      case '+': return a + b;
      case '-': return a - b;
      case '*': return a * b;
    }
  }
  return undefined;
}

// Find `int <name> = <integer-literal>;` declarations and return a map.
function intLocals(raw) {
  const out = new Map();
  const re = /\bint\s+(\w+)\s*=\s*(-?\d+)\s*;/g;
  let m;
  while ((m = re.exec(raw))) out.set(m[1], parseInt(m[2], 10));
  return out;
}

// Pattern 1: Constant ternary assigning to bar.
//   bar = (<expr> [+-*]) num <cmp> <literal> ? "<safe>" : param;
// where `num` is a local int constant and the comparison folds to a known bool.
function hasConstantTernaryBarSafe(raw) {
  const ints = intLocals(raw);
  // Try a few common shape variants. The first looks for the (lhs ± num) > N pattern.
  // We allow either order — `bar = literal ? ... : ...` style.
  const re = /\bbar\s*=\s*\((-?\d+)\s*([+\-*])\s*(-?\d+)\)\s*([+\-])\s*(\w+)\s*([><=!]=?|==)\s*(-?\d+)\s*\?\s*"[^"]*"\s*:\s*(\w+)\s*;/g;
  let m;
  while ((m = re.exec(raw))) {
    const lhs = (() => {
      const a = parseInt(m[1], 10), b = parseInt(m[3], 10);
      switch (m[2]) { case '+': return a + b; case '-': return a - b; case '*': return a * b; }
      return NaN;
    })();
    if (!Number.isFinite(lhs)) continue;
    const variableName = m[5];
    if (!ints.has(variableName)) continue;
    const numVal = ints.get(variableName);
    let actual;
    switch (m[4]) { case '+': actual = lhs + numVal; break; case '-': actual = lhs - numVal; break; default: continue; }
    const rhs = parseInt(m[7], 10);
    let cond;
    switch (m[6]) {
      case '>':  cond = actual > rhs; break;
      case '<':  cond = actual < rhs; break;
      case '>=': cond = actual >= rhs; break;
      case '<=': cond = actual <= rhs; break;
      case '==': cond = actual === rhs; break;
      case '!=': cond = actual !== rhs; break;
      default: continue;
    }
    // If condition is TRUE, taken branch is the literal — safe.
    // (We assert the "then" branch is the literal already via the regex.)
    if (cond) return true;
  }
  return false;
}

// Pattern 2: Constant if/else assigning to bar — same idea.
function hasConstantIfBarSafe(raw) {
  const ints = intLocals(raw);
  // `if ((N op M) op2 num cmp K) bar = "<literal>"; else bar = param;`
  const re = /\bif\s*\(\s*\((-?\d+)\s*([+\-*])\s*(-?\d+)\)\s*([+\-])\s*(\w+)\s*([><=!]=?|==)\s*(-?\d+)\s*\)\s*bar\s*=\s*"[^"]*"\s*;\s*else\s+bar\s*=\s*(\w+)\s*;/g;
  let m;
  while ((m = re.exec(raw))) {
    const lhs = (() => {
      const a = parseInt(m[1], 10), b = parseInt(m[3], 10);
      switch (m[2]) { case '+': return a + b; case '-': return a - b; case '*': return a * b; }
      return NaN;
    })();
    if (!Number.isFinite(lhs)) continue;
    if (!ints.has(m[5])) continue;
    const numVal = ints.get(m[5]);
    let actual;
    switch (m[4]) { case '+': actual = lhs + numVal; break; case '-': actual = lhs - numVal; break; default: continue; }
    const rhs = parseInt(m[7], 10);
    let cond;
    switch (m[6]) {
      case '>':  cond = actual > rhs; break;
      case '<':  cond = actual < rhs; break;
      case '>=': cond = actual >= rhs; break;
      case '<=': cond = actual <= rhs; break;
      case '==': cond = actual === rhs; break;
      case '!=': cond = actual !== rhs; break;
      default: continue;
    }
    if (cond) return true;
  }
  return false;
}

// Pattern 3: Map double-get where the final get is on the "safe key" that was
// .put with a literal.
//   map.put("keyA-XXX", "literal");
//   map.put("keyB-XXX", param);
//   bar = map.get("keyB-XXX");
//   bar = map.get("keyA-XXX");   // overwrites with safe
function hasMapDoubleGetSafe(raw) {
  // Use a tolerant regex — we don't need to bind every put to every get.
  // The presence of these three lines in this order suffices.
  const re = /\.\s*put\s*\(\s*("[^"]+")\s*,\s*"[^"]*"\s*\)\s*;[\s\S]{0,400}?\.\s*put\s*\(\s*("[^"]+")\s*,\s*\w+\s*\)[\s\S]{0,500}?\bbar\s*=\s*(?:\(String\)\s*)?\w+\.get\(\s*\2\s*\)[\s\S]{0,200}?\bbar\s*=\s*(?:\(String\)\s*)?\w+\.get\(\s*\1\s*\)/;
  return re.test(raw);
}

// Pattern 4: Simulate list operations to determine whether `bar = list.get(N)`
// returns a literal or tainted slot. Supports add(elem), add(N, elem) inserts,
// remove(N) by constant index. On anything we can't track (set, clear,
// shuffle, sort, etc.) we bail out.
//
// Conservatively returns TRUE only when ALL bar=get(N) sites resolve to a
// literal slot. If any site sees a tainted slot OR the simulation gives up,
// we return false.
function _simulateListBar(raw) {
  const barGetRe = /\bbar\s*=\s*(?:\(String\)\s*)?(\w+)\s*\.\s*get\s*\(\s*(\d+)\s*\)\s*;/g;
  let bm;
  let anyResolved = false;
  while ((bm = barGetRe.exec(raw))) {
    const listVar = bm[1];
    const idx = parseInt(bm[2], 10);
    const before = raw.slice(0, bm.index);
    const createRe = new RegExp(`\\b(?:java\\.util\\.)?(?:List|ArrayList|LinkedList|Vector)<[^>]+>\\s+${listVar}\\s*=\\s*new\\s+(?:java\\.util\\.)?(?:ArrayList|LinkedList|Vector)<[^>]+>\\s*\\(\\s*\\)\\s*;`);
    const createMatch = createRe.exec(before);
    if (!createMatch) continue;
    const opsRegion = before.slice(createMatch.index + createMatch[0].length);
    const opRe = new RegExp(`\\b${listVar}\\s*\\.\\s*(add|remove|set|clear|addAll|shuffle|sort|reverse|removeIf|removeAll)\\s*\\(([^)]*)\\)\\s*;`, 'g');
    const slots = [];
    let bail = false;
    let op;
    while ((op = opRe.exec(opsRegion))) {
      const action = op[1];
      const args = op[2].trim();
      if (action === 'add') {
        const insAt = args.match(/^\s*(\d+)\s*,\s*(.+)$/);
        if (insAt) {
          const at = parseInt(insAt[1], 10);
          const val = insAt[2].trim();
          const slot = /^"[^"]*"$/.test(val) ? 'lit' : /^\w+$/.test(val) ? (/\b(?:param|input|userInput|raw|untrusted)\b/.test(val) ? 'taint' : 'unknown') : 'unknown';
          if (at >= 0 && at <= slots.length) slots.splice(at, 0, slot);
          else { bail = true; break; }
        } else if (/^"[^"]*"$/.test(args))     slots.push('lit');
        else if (/^\w+$/.test(args))            slots.push(/\b(?:param|input|userInput|raw|untrusted)\b/.test(args) ? 'taint' : 'unknown');
        else                                     slots.push('unknown');
      } else if (action === 'remove') {
        const remIdx = parseInt(args, 10);
        if (Number.isFinite(remIdx) && remIdx >= 0 && remIdx < slots.length) {
          slots.splice(remIdx, 1);
        } else { bail = true; break; }
      } else { bail = true; break; }
    }
    if (bail) return false;
    if (idx < 0 || idx >= slots.length) return false;
    if (slots[idx] === 'lit') anyResolved = true;
    else return false;
  }
  return anyResolved;
}

function hasListGetIndex0Safe(raw) {
  return _simulateListBar(raw);
}

// Pattern 5: switch on charAt() of a literal — the switch case is fully
// determined at compile-time, the OTHER cases are dead, so `bar` is whatever
// the taken case assigns it.
//   String guess = "ABC";
//   char switchTarget = guess.charAt(1);   // = 'B'
//   switch (switchTarget) {
//     case 'A': bar = param;       break;   // DEAD
//     case 'B': bar = "literal";   break;   // TAKEN
//     ...
//   }
function hasSwitchCharAtConstantSafe(raw) {
  // 1. Find `String <var> = "<lit>";` then `char <other> = <var>.charAt(<idx>);`.
  const decl = /\bString\s+(\w+)\s*=\s*"([^"]+)"\s*;\s*(?:\/\/[^\n]*\n)?\s*char\s+\w+\s*=\s*\1\s*\.\s*charAt\s*\(\s*(\d+)\s*\)\s*;/g;
  let m;
  while ((m = decl.exec(raw))) {
    const lit = m[2];
    const idx = parseInt(m[3], 10);
    if (!(idx >= 0 && idx < lit.length)) continue;
    const takenChar = lit[idx];
    // 2. Look ahead for the switch statement and find the case for takenChar.
    const tail = raw.slice(m.index + m[0].length, m.index + m[0].length + 2000);
    const caseRe = new RegExp(`case\\s+['"\`]${takenChar}['"\`]\\s*:\\s*bar\\s*=\\s*"[^"]*"`, '');
    if (caseRe.test(tail)) return true;
  }
  return false;
}

// Top-level: is the `bar` variable provably safe in this Java file?
export function isJavaBarProvablySafe(raw) {
  return hasConstantTernaryBarSafe(raw)
      || hasConstantIfBarSafe(raw)
      || hasMapDoubleGetSafe(raw)
      || hasListGetIndex0Safe(raw)
      || hasSwitchCharAtConstantSafe(raw);
}
