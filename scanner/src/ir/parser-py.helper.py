#!/usr/bin/env python3
# Python IR helper for the agentic-security scanner.
#
# Reads a JSON list `[{"file": "...", "content": "..."}, ...]` from stdin.
# For each file, walks the Python AST (stdlib `ast`, no external deps) and
# emits the same IR shape the regex-based `parser-py.js` produces, but
# computed from a real parser. Writes a JSON array of `{file, functions[],
# topLevel}` blobs to stdout.
#
# IR shape (must mirror parser-py.js):
#
#   { file, functions: [
#       { qid, name, line, params, file,
#         cfg: { entry: nodeId, exit: nodeId, nodes: { id: node } } }
#     ], topLevel: <qid of synthetic <module> function, or null if the file
#                   has no top-level statements worth lowering (PRD R14(b))> }
#
#   node = {
#     kind: 'entry' | 'exit' | 'noop' | 'loop-header' | 'assign' | 'call'
#           | 'if' | 'return' | 'throw' | 'unknown',
#     line, succ: [nodeId, ...], pred: [nodeId, ...],
#     ...kind-specific fields
#   }
#
#   For assign: { target: str|None, source: expr }
#   For call:   { callee: str, args: [expr] }
#   For if:     { cond: expr }
#   For return: { value: expr|None }
#
#   expr = { kind: 'literal'|'ident'|'member'|'binary'|'logical'|'tpl'
#                  |'call'|'array'|'object'|'unknown',
#            ...kind-specific fields }
#
# Constructs deliberately NOT yet lowered (emit `kind: 'unknown'`):
#   - match statements (we tag the function as having one, but don't
#     control-flow into it; future work).
#   - walrus assignment :=
#   - nested function defs inside comprehensions
#   - decorators (function records keep the @-decorator names as metadata
#     but the decorator expressions don't get full CFG nodes).
#
# Exit codes:
#   0   success — stdout is JSON
#   2   bad input (stdin not parseable)
#   3   no Python files in input
#
# This script is invoked by `scanner/src/ir/parser-py-cst.js`; never run
# directly by the scanner user.

import ast
import hashlib
import json
import sys
from typing import Any, Optional


# ─── ID generation ───────────────────────────────────────────────────────────

_node_id = 0


def _next_id() -> str:
    global _node_id
    _node_id += 1
    return f"pyn{_node_id}"


def _qid(file: str, name: str, line: int) -> str:
    h = hashlib.sha1(f"{file}:{name}:{line}".encode("utf-8")).hexdigest()[:8]
    return f"{file}::{name}@{line}#{h}"


# ─── Expression lowering ─────────────────────────────────────────────────────


def _lower_expr(node: ast.AST) -> dict[str, Any]:
    if node is None:
        return {"kind": "unknown"}
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, str):
            return {"kind": "literal", "value": repr(v)}
        if isinstance(v, (int, float, bool)) or v is None:
            return {"kind": "literal", "value": v if v is not None else "None"}
        return {"kind": "literal", "value": repr(v)}
    if isinstance(node, ast.Name):
        return {"kind": "ident", "name": node.id}
    if isinstance(node, ast.Attribute):
        return {"kind": "member", "object": _lower_expr(node.value), "prop": node.attr}
    if isinstance(node, ast.Subscript):
        # Surface as a member-with-slice; downstream taint treats it like member access.
        return {
            "kind": "member",
            "object": _lower_expr(node.value),
            "prop": "[]",
        }
    if isinstance(node, ast.JoinedStr):
        # f"...{expr}..." — taint flows through the interpolated parts.
        parts = []
        for p in node.values:
            if isinstance(p, ast.FormattedValue):
                parts.append(_lower_expr(p.value))
        return {"kind": "tpl", "parts": parts}
    if isinstance(node, ast.BinOp):
        op = type(node.op).__name__
        return {
            "kind": "binary", "op": op,
            "left": _lower_expr(node.left),
            "right": _lower_expr(node.right),
        }
    if isinstance(node, ast.BoolOp):
        # 'and' / 'or' — preserve as logical with first two values for taint analysis.
        # (Multi-arg BoolOp ` a or b or c ` is left-associated into nested logical.)
        kind = "logical"
        op = "and" if isinstance(node.op, ast.And) else "or"
        vs = node.values or []
        if len(vs) == 0:
            return {"kind": "unknown"}
        cur = _lower_expr(vs[0])
        for v in vs[1:]:
            cur = {"kind": kind, "op": op, "left": cur, "right": _lower_expr(v)}
        return cur
    if isinstance(node, ast.Compare):
        # Treat as binary on first operand pair (taint analysis doesn't need full chain).
        left = _lower_expr(node.left)
        right = _lower_expr(node.comparators[0]) if node.comparators else {"kind": "unknown"}
        op = type(node.ops[0]).__name__ if node.ops else "Eq"
        return {"kind": "binary", "op": op, "left": left, "right": right}
    if isinstance(node, ast.Call):
        callee = _flatten_callee(node.func)
        args = [_lower_expr(a) for a in (node.args or [])]
        # Keyword args lowered as positional — taint analysis treats them similarly.
        for kw in (node.keywords or []):
            args.append(_lower_expr(kw.value))
        return {"kind": "call", "callee": callee, "args": args}
    if isinstance(node, ast.List) or isinstance(node, ast.Tuple) or isinstance(node, ast.Set):
        return {"kind": "array", "elements": [_lower_expr(e) for e in (node.elts or [])]}
    if isinstance(node, ast.Dict):
        return {
            "kind": "object",
            "props": [
                {"value": _lower_expr(v)} for v in (node.values or [])
            ],
        }
    if isinstance(node, ast.IfExp):
        # Ternary `a if cond else b` — surface as union of both branches.
        return {
            "kind": "union",
            "branches": [_lower_expr(node.body), _lower_expr(node.orelse)],
        }
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        # Comprehension — represent as array whose element is the lowered
        # elt expression. Tracks taint through `[x for x in untrusted]`.
        return {
            "kind": "array",
            "elements": [_lower_expr(node.elt)],
        }
    if isinstance(node, ast.DictComp):
        return {
            "kind": "object",
            "props": [{"value": _lower_expr(node.value)}],
        }
    if isinstance(node, ast.Lambda):
        # Body of lambda lowered as a transparent expression; the body's
        # free vars surface through the union.
        return _lower_expr(node.body)
    if isinstance(node, ast.Starred):
        return _lower_expr(node.value)
    if isinstance(node, ast.NamedExpr):
        # Walrus: `(x := expr)` — surface both the target binding and the value.
        return {
            "kind": "union",
            "branches": [
                {"kind": "ident", "name": node.target.id},
                _lower_expr(node.value),
            ],
        }
    if isinstance(node, ast.UnaryOp):
        return _lower_expr(node.operand)
    if isinstance(node, ast.Await):
        return _lower_expr(node.value)
    if isinstance(node, ast.Yield):
        return _lower_expr(node.value) if node.value else {"kind": "unknown"}
    if isinstance(node, ast.YieldFrom):
        return _lower_expr(node.value)
    return {"kind": "unknown"}


def _flatten_callee(node: ast.AST) -> Any:
    """Return a dot-joined name like 'os.path.join' for a callee, or a
    structured member-access tree for harder shapes. The dataflow engine
    handles both forms."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        # Walk inward collecting names.
        parts: list[str] = []
        cur: Any = node
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
            return ".".join(parts)
        # Mixed shape (e.g. `func()[0].attr`) — fall back to ident name.
        return parts[-1] if parts else None
    if isinstance(node, ast.Call):
        # Chained calls — surface the immediate callee.
        return _flatten_callee(node.func)
    if isinstance(node, ast.Subscript):
        return _flatten_callee(node.value)
    return None


def _assign_target(node: ast.AST) -> "str | list[str] | None":
    """Return a single identifier, dotted-path string, or a list of targets
    for destructuring assignments (Tuple/List unpacking)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: Any = node
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
            return ".".join(parts)
    if isinstance(node, (ast.Tuple, ast.List)):
        targets = []
        for elt in node.elts:
            t = _assign_target(elt)
            targets.append(t if isinstance(t, str) else None)
        return targets
    if isinstance(node, ast.Starred):
        return _assign_target(node.value)
    return None


def _lower_match_pattern(pattern: ast.AST, subject: dict) -> dict:
    """Lower a match-case pattern to an expression for the if-condition."""
    if isinstance(pattern, ast.MatchValue):
        return {"kind": "binary", "op": "Eq", "left": subject, "right": _lower_expr(pattern.value)}
    if isinstance(pattern, ast.MatchSingleton):
        return {"kind": "binary", "op": "Is", "left": subject, "right": {"kind": "literal", "value": pattern.value}}
    if isinstance(pattern, ast.MatchAs):
        if pattern.pattern is not None:
            return _lower_match_pattern(pattern.pattern, subject)
        return {"kind": "unknown"}
    if isinstance(pattern, ast.MatchOr):
        if pattern.patterns:
            return _lower_match_pattern(pattern.patterns[0], subject)
        return {"kind": "unknown"}
    return {"kind": "unknown"}


def _match_pattern_capture(pattern: ast.AST) -> Optional[str]:
    """Extract the capture variable name from a match-case pattern, if any."""
    if isinstance(pattern, ast.MatchAs):
        return pattern.name
    if isinstance(pattern, ast.MatchStar) and hasattr(pattern, "name"):
        return pattern.name
    return None


# ─── CFG construction ────────────────────────────────────────────────────────


class CfgBuilder:
    """Walks a function body and emits a CFG matching the regex parser's shape."""

    def __init__(self, fn_name: str) -> None:
        self.fn_name = fn_name
        self.nodes: dict[str, dict[str, Any]] = {}
        self.entry = self._add({"kind": "entry", "line": 0})
        self.exit = self._add({"kind": "exit", "line": 0})

    def _add(self, node: dict[str, Any]) -> str:
        nid = _next_id()
        node.setdefault("succ", [])
        node.setdefault("pred", [])
        self.nodes[nid] = node
        return nid

    def _link(self, src_id: str, dst_id: str) -> None:
        sn = self.nodes[src_id]
        dn = self.nodes[dst_id]
        if dst_id not in sn["succ"]:
            sn["succ"].append(dst_id)
        if src_id not in dn["pred"]:
            dn["pred"].append(src_id)

    @staticmethod
    def _collect_walrus(node: ast.AST) -> list[ast.NamedExpr]:
        """Collect all NamedExpr (walrus) nodes from an expression tree."""
        out: list[ast.NamedExpr] = []
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                out.append(child)
        return out

    def _emit_walrus_assigns(self, expr_node: ast.AST, prev: str, line: int) -> str:
        """Emit assign nodes for any walrus operators in an expression."""
        for w in self._collect_walrus(expr_node):
            a = self._add({
                "kind": "assign",
                "target": w.target.id,
                "source": _lower_expr(w.value),
                "line": line,
            })
            self._link(prev, a)
            prev = a
        return prev

    def lower(self, body: list[ast.stmt]) -> None:
        tail = self.entry
        tail = self._lower_block(body, tail)
        self._link(tail, self.exit)

    def _lower_block(self, body: list[ast.stmt], prev: str) -> str:
        """Lower a sequential list of statements; return the tail node id."""
        for stmt in body:
            prev = self._lower_stmt(stmt, prev)
        return prev

    def _lower_stmt(self, stmt: ast.stmt, prev: str) -> str:
        line = getattr(stmt, "lineno", 0) or 0
        if isinstance(stmt, ast.Expr):
            # Bare expression — useful when it's a call (decorator pattern,
            # dispatch shape). For everything else, noop.
            if isinstance(stmt.value, ast.Call):
                cur = self._add({
                    "kind": "call",
                    "callee": _flatten_callee(stmt.value.func),
                    "args": [_lower_expr(a) for a in (stmt.value.args or [])]
                          + [_lower_expr(kw.value) for kw in (stmt.value.keywords or [])],
                    "line": line,
                })
            elif isinstance(stmt.value, ast.NamedExpr):
                cur = self._add({
                    "kind": "assign",
                    "target": stmt.value.target.id,
                    "source": _lower_expr(stmt.value.value),
                    "line": line,
                })
            else:
                cur = self._add({"kind": "noop", "line": line})
            self._link(prev, cur)
            return cur
        if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            # AugAssign: x += y  → assign x = x + y
            # AnnAssign: x: int = y → assign x = y (or noop if no value)
            if isinstance(stmt, ast.AugAssign):
                tgt = _assign_target(stmt.target)
                src = {
                    "kind": "binary",
                    "op": type(stmt.op).__name__,
                    "left": {"kind": "ident", "name": tgt or "?"},
                    "right": _lower_expr(stmt.value),
                }
            elif isinstance(stmt, ast.AnnAssign):
                tgt = _assign_target(stmt.target)
                if stmt.value is None:
                    cur = self._add({"kind": "noop", "line": line})
                    self._link(prev, cur)
                    return cur
                src = _lower_expr(stmt.value)
            else:
                # ast.Assign: targets may be multi (a = b = c). We use the first.
                tgt = _assign_target(stmt.targets[0]) if stmt.targets else None
                src = _lower_expr(stmt.value)
            if isinstance(tgt, list):
                # Destructuring: a, b = expr → one assign per element.
                rhs = src
                tail = prev
                for i, t in enumerate(tgt):
                    elem_src = {"kind": "member", "object": rhs, "prop": "[]"}
                    a = self._add({"kind": "assign", "target": t, "source": elem_src, "line": line})
                    self._link(tail, a)
                    tail = a
                return tail
            # Comprehension with filters at statement level: emit filter conditions.
            rhs_node = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
            if rhs_node and isinstance(rhs_node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                tail = prev
                for gen in rhs_node.generators:
                    # Emit loop var assign from iter
                    loop_tgt = _assign_target(gen.target)
                    if loop_tgt and isinstance(loop_tgt, str):
                        la = self._add({
                            "kind": "assign", "target": loop_tgt,
                            "source": _lower_expr(gen.iter), "line": line,
                        })
                        self._link(tail, la)
                        tail = la
                    for if_clause in gen.ifs:
                        if_n = self._add({
                            "kind": "if",
                            "cond": _lower_expr(if_clause),
                            "line": line,
                        })
                        self._link(tail, if_n)
                        tail = if_n
                cur = self._add({"kind": "assign", "target": tgt if isinstance(tgt, str) else None, "source": src, "line": line})
                self._link(tail, cur)
                return cur
            cur = self._add({"kind": "assign", "target": tgt, "source": src, "line": line})
            self._link(prev, cur)
            return cur
        if isinstance(stmt, ast.If):
            prev = self._emit_walrus_assigns(stmt.test, prev, line)
            if_node = self._add({
                "kind": "if",
                "cond": _lower_expr(stmt.test),
                "line": line,
            })
            self._link(prev, if_node)
            t_tail = self._lower_block(stmt.body, if_node)
            join = self._add({"kind": "noop", "line": line})
            self._link(t_tail, join)
            if stmt.orelse:
                f_tail = self._lower_block(stmt.orelse, if_node)
                self._link(f_tail, join)
            else:
                self._link(if_node, join)
            return join
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            # for v in iter: body → assign v from iter; loop-header; body
            lh = self._add({"kind": "loop-header", "line": line})
            self._link(prev, lh)
            # Synthesize an assign for the loop variable so taint from the iter
            # propagates to `v`. Only when target is a plain name.
            tgt = _assign_target(stmt.target)
            if tgt is not None:
                a = self._add({
                    "kind": "assign", "target": tgt,
                    "source": _lower_expr(stmt.iter), "line": line,
                })
                self._link(lh, a)
                body_prev = a
            else:
                body_prev = lh
            body_tail = self._lower_block(stmt.body, body_prev)
            self._link(body_tail, lh)
            # Loop exit edge (taken when condition false) goes to a join.
            join = self._add({"kind": "noop", "line": line})
            self._link(lh, join)
            return join
        if isinstance(stmt, (ast.While,)):
            prev = self._emit_walrus_assigns(stmt.test, prev, line)
            lh = self._add({"kind": "loop-header", "line": line})
            self._link(prev, lh)
            body_tail = self._lower_block(stmt.body, lh)
            self._link(body_tail, lh)
            join = self._add({"kind": "noop", "line": line})
            self._link(lh, join)
            return join
        if isinstance(stmt, ast.Return):
            cur = self._add({
                "kind": "return",
                "value": _lower_expr(stmt.value) if stmt.value else None,
                "line": line,
            })
            self._link(prev, cur)
            # Return implicitly flows to exit. We don't link here; the outer
            # `lower` method links the final tail to exit, and the engine
            # treats return as terminal.
            return cur
        if isinstance(stmt, ast.Raise):
            cur = self._add({"kind": "throw", "line": line})
            self._link(prev, cur)
            return cur
        if isinstance(stmt, ast.Try):
            # try body + except handlers + finally. Treat the try body as a
            # plain sequential block; each except handler is an alternate
            # branch from the try head; finally runs after the union. This
            # is a conservative over-approximation that doesn't add false
            # taint but does see every reachable path.
            try_head = self._add({"kind": "noop", "line": line})
            self._link(prev, try_head)
            body_tail = self._lower_block(stmt.body, try_head)
            join = self._add({"kind": "noop", "line": line})
            self._link(body_tail, join)
            for handler in stmt.handlers:
                h_tail = self._lower_block(handler.body, try_head)
                self._link(h_tail, join)
            if stmt.orelse:
                else_tail = self._lower_block(stmt.orelse, body_tail)
                self._link(else_tail, join)
            if stmt.finalbody:
                fin_tail = self._lower_block(stmt.finalbody, join)
                return fin_tail
            return join
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            # Treat `with X() as v: body` as `v = X()`-style assign followed by body.
            tail = prev
            for item in stmt.items:
                tgt = _assign_target(item.optional_vars) if item.optional_vars else None
                if tgt is not None:
                    a = self._add({
                        "kind": "assign", "target": tgt,
                        "source": _lower_expr(item.context_expr), "line": line,
                    })
                    self._link(tail, a)
                    tail = a
            return self._lower_block(stmt.body, tail)
        if isinstance(stmt, ast.FunctionDef) or isinstance(stmt, ast.AsyncFunctionDef):
            # Nested function definition — emit a noop placeholder. The outer
            # extractor handles nested functions separately via ast.walk().
            cur = self._add({"kind": "noop", "line": line})
            self._link(prev, cur)
            return cur
        if isinstance(stmt, ast.ClassDef):
            cur = self._add({"kind": "noop", "line": line})
            self._link(prev, cur)
            return cur
        if isinstance(stmt, ast.Match):
            subject = _lower_expr(stmt.subject)
            join = self._add({"kind": "noop", "line": line})
            for case in stmt.cases:
                case_line = getattr(case, "lineno", line) or line
                pattern_expr = _lower_match_pattern(case.pattern, subject)
                if_node = self._add({
                    "kind": "if",
                    "cond": pattern_expr,
                    "line": case_line,
                })
                self._link(prev, if_node)
                # If pattern has a capture name, emit an assign for it.
                capture = _match_pattern_capture(case.pattern)
                if capture:
                    a = self._add({
                        "kind": "assign", "target": capture,
                        "source": subject, "line": case_line,
                    })
                    self._link(if_node, a)
                    body_prev = a
                else:
                    body_prev = if_node
                body_tail = self._lower_block(case.body, body_prev)
                self._link(body_tail, join)
            self._link(prev, join)
            return join
        # ast.Pass, ast.Break, ast.Continue, ast.Import, ast.ImportFrom,
        # ast.Global, ast.Nonlocal, ast.Delete — all noops for taint.
        cur = self._add({"kind": "noop", "line": line})
        self._link(prev, cur)
        return cur


# ─── Function extraction ─────────────────────────────────────────────────────


def _extract_functions(tree: ast.Module, file: str) -> list[dict[str, Any]]:
    """Walk the module, capturing every function (top-level or nested) into
    a flat list. Each function's body is lowered into a CFG."""
    fns: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = [a.arg for a in node.args.args]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        if node.args.kwarg:
            params.append(node.args.kwarg.arg)
        for a in node.args.kwonlyargs:
            params.append(a.arg)
        line = node.lineno or 0
        builder = CfgBuilder(node.name)
        builder.lower(node.body)
        fns.append({
            "qid": _qid(file, node.name, line),
            "name": node.name,
            "line": line,
            "params": params,
            "file": file,
            "cfg": {
                "entry": builder.entry,
                "exit": builder.exit,
                "nodes": builder.nodes,
            },
        })
    return fns


# ─── Driver ──────────────────────────────────────────────────────────────────


def _process_one(file: str, content: str) -> dict[str, Any]:
    if not isinstance(content, str):
        return {"file": file, "functions": [], "topLevel": None, "_error": "content-not-string"}
    if len(content) > 1_000_000:
        return {"file": file, "functions": [], "topLevel": None, "_error": "file-too-large"}
    try:
        tree = ast.parse(content, filename=file)
    except SyntaxError as e:
        return {"file": file, "functions": [], "topLevel": None, "_error": f"syntax-error: {e.msg} (line {e.lineno})"}
    fns = _extract_functions(tree, file)
    # R14(b): lower top-level (module-scope) statements into a synthetic
    # <module> function, mirroring parser-js.js's Program-level lowering.
    # Only included when it carries real content — a FunctionDef/ClassDef
    # encountered here lowers to a noop placeholder (_lower_stmt already
    # does this so nested defs aren't double-counted; see _extract_functions
    # above, which independently captures them via ast.walk), so a
    # function-only file must not gain a <module> entry just because its
    # single top-level statement happens to be a def.
    mod_builder = CfgBuilder("<module>")
    mod_builder.lower(tree.body)
    mod_has_content = any(
        n.get("kind") not in ("entry", "exit", "noop")
        for n in mod_builder.nodes.values()
    )
    top_level_qid = None
    if mod_has_content:
        top_level_qid = _qid(file, "<module>", 1)
        fns.append({
            "qid": top_level_qid,
            "name": "<module>",
            "line": 1,
            "params": [],
            "file": file,
            "cfg": {
                "entry": mod_builder.entry,
                "exit": mod_builder.exit,
                "nodes": mod_builder.nodes,
            },
        })
    return {"file": file, "functions": fns, "topLevel": top_level_qid}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception as e:
        sys.stderr.write(f"parser-py.helper: bad stdin JSON: {e}\n")
        return 2
    if not isinstance(payload, list):
        sys.stderr.write("parser-py.helper: stdin must be a JSON array\n")
        return 2
    out: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        file = entry.get("file") or ""
        if not file.endswith(".py"):
            continue
        content = entry.get("content") or ""
        out.append(_process_one(file, content))
    if not out:
        sys.stderr.write("parser-py.helper: no .py files in input\n")
        return 3
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
