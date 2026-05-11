// True positive: nested quantifier — classic catastrophic backtracking
const NESTED_PLUS = /^(a+)+$/;

// True positive: overlapping alternation under * — (a|aa)*
const OVERLAP = /^(a|aa)*$/;

// True positive: nested group with quantifier
const NESTED_GROUP = /^(?:[a-z]+)+$/;

// False positive shape: non-overlapping char-class alternation
// `[^"\\]` and `\\.` consume disjoint inputs — no fork, linear time.
const PY_FSTRING = /\bf"(?:[^"\\]|\\.)*"|\bf'(?:[^'\\]|\\.)*'/g;

// False positive shape: bounded char class with no nested quantifier
const SAFE_TOKEN = /^[A-Za-z0-9_]+$/;

// False positive: literal alternation, no quantifier
const SIMPLE_ALT = /(foo|bar|baz)/;
