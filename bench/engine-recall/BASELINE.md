# Engine recall gaps — before measurement

Date: 2026-07-27
Commit: d017ee8684d18329c3f2c410c975f4e4170bc393 (branch `fix/engine-recall-gaps`, no engine changes)

Captured via:

```bash
cd scanner
npm run bench:engine-recall
```

## Defect 1: assignment-position sink call

Identical taint flow (`req.query.c` -> local var -> `exec()`); the only
difference between the two snippets is whether the sink call is a bare
statement or sits on the right-hand side of an assignment.

| Position | total findings | IR-TAINT findings |
|---|---|---|
| statement: `exec(c);` | 1 | 1 |
| assignment: `const out = exec(c);` | 0 | 0 |

The assignment-position call produces zero findings — the sink is silently
missed when its result is assigned to a variable.

## Defect 2: `match.type: 'global'` catalog sources are unreachable

`matchSource()` was probed with both an `ident` AST node and a `member`
node (root identifier) for every catalog entry declared `match.type: 'global'`.

- Total `global`-type entries in `CATALOG`: 10
- Reachable via `matchSource()`: 0
- By language: `{"js":1,"rb":4,"php":5}`

None of the 10 global-source catalog entries (spanning JS, Ruby, and PHP —
including PHP's `$_GET`/`$_POST`/etc. family) are currently reachable from
`matchSource()`.

## Raw output

```
assign-sink  statement: total=1 irTaint=1
assign-sink  assignment: total=0 irTaint=0
global-sources reachable=0/10 {"js":1,"rb":4,"php":5}
```

```json
{
  "assignSink": {
    "statement": { "total": 1, "irTaint": 1 },
    "assignment": { "total": 0, "irTaint": 0 }
  },
  "globalSources": {
    "total": 10,
    "reachable": 0,
    "byLanguage": { "js": 1, "rb": 4, "php": 5 }
  }
}
```

These figures match the reproduction that motivated this plan exactly:
statement `total=1 irTaint=1`, assignment `total=0 irTaint=0`, global sources
`0/10`. No deviation — the defects are as described.
