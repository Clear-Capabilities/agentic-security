// Tests for sast/java-ast-folding.js's constant-folding dead-branch
// detector, consumed by java-bench-extras.js's applyJavaBenchSuppressions
// to suppress findings inside PROVABLY unreachable branches.
//
// SARD_80_F1 W4.J4 follow-up: `deadBranchRanges` tracked a variable's
// constant value across an ENTIRE function body, but explicitly did not
// bind new values for assignments inside a block it "descends but doesn't
// bind constants" for (try/loop/switch bodies) — yet it also never
// INVALIDATED the stale pre-block value it already had. The canonical Java
// idiom `T x = null; try { x = source(); } catch (...) {} if (x != null) {
// sink(x); }` (Juliet's OWN dominant shape for URLConnection/network-read
// sources) was constant-folded as if `x` were STILL `null` at the `if`
// check, marking the sink-bearing then-branch "constant-false-if dead-then"
// and silently deleting the finding inside it — a false negative, not a
// suppressed false positive. Confirmed via SARD's CWE-83 corpus: every one
// of its 25 URLConnection flow variants used this exact shape with a `null`
// initializer; the File-sourced variants happened to initialize with `""`
// instead, which sidesteps the bug by accident (`"" != null` folds to
// constant-TRUE, marking the absent else-branch dead instead).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deadBranchRanges, isLineInDeadRange } from '../src/sast/java-ast-folding.js';

test('a variable reassigned inside a try block before a null-check is NOT folded to dead code', () => {
  const src = `
    import javax.servlet.http.*;
    public class Bad extends HttpServlet {
        public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable {
            String data = null;
            try {
                data = request.getParameter("q");
            } catch (Exception e) {}
            if (data != null) {
                response.getWriter().println("<img src=\\"" + data + "\\">");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0,
    `expected no dead ranges (data is reassigned in the try block), got: ${JSON.stringify(ranges)}`);
});

test('a variable reassigned inside a for-loop before a check is NOT folded to dead code', () => {
  const src = `
    public class Bad {
        public void bad() {
            boolean flag = false;
            for (int i = 0; i < 1; i++) {
                flag = true;
            }
            if (flag) {
                System.out.println("reachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0,
    `expected no dead ranges (flag is reassigned in the loop), got: ${JSON.stringify(ranges)}`);
});

test('a variable incremented inside a loop before a check is NOT folded to dead code', () => {
  const src = `
    public class Bad {
        public void bad() {
            int count = 0;
            for (int i = 0; i < 3; i++) {
                count++;
            }
            if (count == 0) {
                System.out.println("should not be considered dead");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0,
    `expected no dead ranges (count is incremented in the loop), got: ${JSON.stringify(ranges)}`);
});

test('a genuinely constant if(false) branch is still correctly detected as dead (no regression)', () => {
  const src = `
    public class Bad {
        public void bad() {
            boolean flag = false;
            if (flag) {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected exactly one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-false-if dead-then');
});

test('a genuinely constant if(true) else-branch is still correctly detected as dead (no regression)', () => {
  const src = `
    public class Bad {
        public void bad() {
            boolean flag = true;
            if (flag) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected exactly one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

// SARD_80_F1 W4.J34 — Juliet's own "Flow Variant 04: Control flow:
// if(PRIVATE_STATIC_FINAL_TRUE) and if(PRIVATE_STATIC_FINAL_FALSE)" idiom
// (confirmed via the public Java Juliet mirror's own
// CWE601_Open_Redirect__Servlet_connect_tcp_04.java) — identical to the
// already-modeled literal if(true)/if(false) shape, except the condition
// is a class-level `private static final boolean` FIELD reference rather
// than the literal keyword.
test('a class-level `private static final boolean` field used as an if-condition is folded (dead else)', () => {
  const src = `
    public class Bad {
        private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;
        public void bad() {
            if (PRIVATE_STATIC_FINAL_TRUE) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected exactly one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

test('a class-level `private static final boolean` field set to false folds the if-branch as dead', () => {
  const src = `
    public class Bad {
        private static final boolean PRIVATE_STATIC_FINAL_FALSE = false;
        public void bad() {
            if (PRIVATE_STATIC_FINAL_FALSE) {
                System.out.println("unreachable");
            } else {
                System.out.println("reachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected exactly one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-false-if dead-then');
});

// SARD_80_F1 W4.J36 — a non-final field that is never reassigned anywhere
// in the file is "effectively final" (the same real Java language concept
// used for lambda/anonymous-class capture) and just as safe to fold as a
// real `final` field. Precision control immediately below confirms a
// GENUINELY reassignable field (the same name, actually written to
// elsewhere) is still correctly left unfolded.
test('a class-level field WITHOUT `final`, but never reassigned anywhere (effectively final), IS folded', () => {
  const src = `
    public class Bad {
        private static boolean notActuallyFinal = true;
        public void bad() {
            if (notActuallyFinal) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected one dead range for an effectively-final field, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

test('a class-level field WITHOUT `final` that IS reassigned elsewhere is NOT folded', () => {
  const src = `
    public class Bad {
        private static boolean notActuallyFinal = true;
        public void reset() {
            notActuallyFinal = false;
        }
        public void bad() {
            if (notActuallyFinal) {
                System.out.println("could be reached if reset() ran first");
            } else {
                System.out.println("could also be reached");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0, `expected no dead ranges for a genuinely reassignable field, got: ${JSON.stringify(ranges)}`);
});

// SARD_80_F1 W4.J36 — Juliet's own Flow Variant 05 ("if(privateTrue) and
// if(privateFalse)") and Flow Variant 07 ("if(privateFive==5) and
// if(privateFive!=5)"), confirmed via the public Java Juliet mirror's own
// CWE601_Open_Redirect__Servlet_connect_tcp_05.java / _07.java.
test('an effectively-final `private boolean` instance field (Flow Variant 05 shape) is folded', () => {
  const src = `
    public class Bad {
        private boolean privateTrue = true;
        public void bad() {
            if (privateTrue) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

test('an effectively-final `private int` field compared with == (Flow Variant 07 shape) is folded', () => {
  const src = `
    public class Bad {
        private int privateFive = 5;
        public void bad() {
            if (privateFive == 5) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

// SARD_80_F1 W5.27 — Juliet's own "Control flow: if(privateReturnsTrue())
// and if(privateReturnsFalse())" idiom (Flow Variant 08/11, confirmed via
// the public Java mirror's own CWE601_Open_Redirect__Servlet_connect_tcp_08
// .java): the if-CONDITION is a call to a same-class, zero-arg, single-
// `return true;`/`return false;`-bodied private helper, not a literal or
// field reference the constant evaluator already resolved.
test('a same-class zero-arg method whose body is exactly `return true;` folds an if-condition call (dead else)', () => {
  const src = `
    public class Bad {
        private boolean privateReturnsTrue() {
            return true;
        }
        public void bad() {
            if (privateReturnsTrue()) {
                System.out.println("reachable");
            } else {
                System.out.println("unreachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-true-if dead-else');
});

test('a same-class zero-arg method whose body is exactly `return false;` folds an if-condition call (dead then)', () => {
  const src = `
    public class Bad {
        private boolean privateReturnsFalse() {
            return false;
        }
        public void bad() {
            if (privateReturnsFalse()) {
                System.out.println("unreachable");
            } else {
                System.out.println("reachable");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected one dead range, got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'constant-false-if dead-then');
});

test('a same-class method with a PARAMETER is NOT folded (a caller-supplied arg could change the outcome)', () => {
  const src = `
    public class Bad {
        private boolean check(boolean flag) {
            return flag;
        }
        public void bad(boolean runtimeFlag) {
            if (check(runtimeFlag)) {
                System.out.println("a");
            } else {
                System.out.println("b");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0, 'a parameterized helper must not be folded to a constant');
});

test('a same-class method with 2+ statements in its body is NOT folded (ambiguous, fails closed)', () => {
  const src = `
    public class Bad {
        private boolean maybeTrue() {
            System.out.println("side effect");
            return true;
        }
        public void bad() {
            if (maybeTrue()) {
                System.out.println("a");
            } else {
                System.out.println("b");
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 0, 'a multi-statement body is ambiguous and must not be folded');
});

// SARD_80_F1 W5.35 — `walkSwitch` computed `matchedAny` but never actually
// consulted it: a `default:` group was UNCONDITIONALLY exempted from
// dead-code marking ("we'll resolve default later" — never finished),
// regardless of whether some OTHER case explicitly matched the scrutinee
// and made `default` provably unreachable. Confirmed via a real-corpus fp
// (Juliet's own Flow Variant 15: `switch(6){case 6: data="foo"; default:
// data=null;}` — case 6 matches 6, so default can never run, but the
// backward literal-scan saw the un-marked `default: data=null;` as the
// "nearest" assignment instead of the genuinely-live `case 6: data="foo";`).
test('a `default:` group is marked dead when another case explicitly matches the scrutinee', () => {
  const src = `
    public class Bad {
        public void bad() {
            String data;
            switch (6) {
            case 6:
                data = "foo";
                break;
            default:
                data = null;
                break;
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  assert.equal(ranges.length, 1, `expected exactly one dead range (the default group), got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'unreachable default (switch on constant, another case matched)');
});
test('a `default:` group is NOT marked dead when no other case matches the scrutinee', () => {
  const src = `
    public class Bad {
        public void bad() {
            String data;
            switch (5) {
            case 6:
                data = null;
                break;
            default:
                data = "foo";
                break;
            }
        }
    }
  `;
  const ranges = deadBranchRanges(src);
  // Only case 6 (which does NOT match scrutinee 5) is dead; default is live.
  assert.equal(ranges.length, 1, `expected exactly one dead range (case 6 only), got: ${JSON.stringify(ranges)}`);
  assert.equal(ranges[0].reason, 'unreachable case (switch on constant)');
});

test('isLineInDeadRange: boundary lines are inclusive, adjacent lines are not', () => {
  const ranges = [{ startLine: 10, endLine: 20 }];
  assert.ok(isLineInDeadRange(10, ranges));
  assert.ok(isLineInDeadRange(20, ranges));
  assert.ok(!isLineInDeadRange(9, ranges));
  assert.ok(!isLineInDeadRange(21, ranges));
});
