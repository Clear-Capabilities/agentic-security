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

test('isLineInDeadRange: boundary lines are inclusive, adjacent lines are not', () => {
  const ranges = [{ startLine: 10, endLine: 20 }];
  assert.ok(isLineInDeadRange(10, ranges));
  assert.ok(isLineInDeadRange(20, ranges));
  assert.ok(!isLineInDeadRange(9, ranges));
  assert.ok(!isLineInDeadRange(21, ranges));
});
