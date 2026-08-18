// Fixture-first rebuild of T4.2 against the real code from GHSA-phj3-59pf-cp83
// (thumbor/thumbor, proportion.py). Written BEFORE the rule was touched.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanResourceExhaustion } from '../src/sast/resource-exhaustion.js';

// Verbatim from thumbor/filters/proportion.py pre/.
const PRE = `
class Filter(BaseFilter):
    @filter_method(BaseFilter.DecimalNumber)
    async def proportion(self, value):
        source_width, source_height = self.context.request.engine.size

        new_width = source_width * value
        new_height = source_height * value

        self.context.request.width = new_width
        self.context.request.height = new_height
`;

const POST = PRE.replace(
  '    async def proportion(self, value):\n        source_width',
  '    async def proportion(self, value):\n        if value <= 0 or value > 1.0:\n            return\n\n        source_width',
);

test('T4.2 fires on the real vulnerable proportion.py (value is a decorated filter-method parameter, not a req/params-named var)', () => {
  const findings = scanResourceExhaustion('proportion.py', PRE);
  assert.ok(findings.length > 0, 'a decorated handler parameter used as a multiplication size should count as externally influenced');
});

test('T4.2 is silent on the real fixed proportion.py (an explicit range check on the parameter)', () => {
  const findings = scanResourceExhaustion('proportion.py', POST);
  assert.equal(findings.length, 0);
});

test('T4.2 checks BOTH operands of a multiplication, not just the first', () => {
  // Regression guard for the m[1] || m[2] bug: the ORIGINAL scanner only ever
  // tested the FIRST captured operand for external influence, so
  // `constant * externally_influenced_var` was invisible even though
  // `externally_influenced_var * constant` (operand order flipped) was not.
  const findings = scanResourceExhaustion('x.py', `
class Filter(BaseFilter):
    @filter_method(BaseFilter.DecimalNumber)
    async def proportion(self, value):
        source_width = 100
        new_width = source_width * value
`);
  assert.ok(findings.length > 0);
});
