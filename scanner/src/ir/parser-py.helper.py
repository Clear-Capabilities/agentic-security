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
import re
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
        # Django class-based views: `self.kwargs` is the URL captures dict. Lowered to a call the catalog names as a source
        # (`django_view.kwargs`) while a View subclass's method is being lowered; elsewhere `self.kwargs` is an ordinary field.
        if _LOWER_CTX.get("view_class") and node.attr == "kwargs" and isinstance(node.value, ast.Name) and node.value.id == "self":
            return {"kind": "call", "callee": "django_view.kwargs", "args": [], "line": getattr(node, "lineno", 0) or 0}
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
        return _lower_call_chain(node)
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


_LOWER_CTX: dict[str, Any] = {"view_class": False}

_RQ_OPTION_KWARGS = {"job_timeout", "result_ttl", "ttl", "failure_ttl", "depends_on", "job_id", "at_front", "meta", "retry", "on_success", "on_failure", "description", "timeout"}


def _dispatch_call(call: ast.Call, line: int) -> "dict[str, Any] | None":
    """A task or job dispatch runs the named function with the given arguments on a worker: `task.delay(a, b)` and
    `task.apply_async(args=[a, b], kwargs={...})` (Celery), `queue.enqueue(fn, a, b)` (RQ), `executor.submit(fn, a, b)`.
    The IR states the call `fn(a, b)` beside the dispatch so the function's body is analysed with those arguments."""
    f = call.func
    if not isinstance(f, ast.Attribute):
        return None
    if f.attr == "delay" and isinstance(f.value, (ast.Name, ast.Attribute)):
        return {"kind": "call", "callee": _flatten_callee(f.value), "args": [_lower_expr(a) for a in call.args] + [_lower_expr(k.value) for k in call.keywords if k.arg], "line": line, "dispatch": "delay"}
    if f.attr == "apply_async" and isinstance(f.value, (ast.Name, ast.Attribute)):
        args: list[dict[str, Any]] = []
        if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
            args += [_lower_expr(a) for a in call.args[0].elts]
        for k in call.keywords:
            if k.arg == "args" and isinstance(k.value, (ast.List, ast.Tuple)):
                args += [_lower_expr(a) for a in k.value.elts]
            elif k.arg == "kwargs" and isinstance(k.value, ast.Dict):
                args += [_lower_expr(v) for v in k.value.values]
        return {"kind": "call", "callee": _flatten_callee(f.value), "args": args, "line": line, "dispatch": "apply_async"}
    if f.attr in ("enqueue", "enqueue_call", "submit") and call.args and isinstance(call.args[0], (ast.Name, ast.Attribute)):
        args = [_lower_expr(a) for a in call.args[1:]] + [_lower_expr(k.value) for k in call.keywords if k.arg and k.arg not in _RQ_OPTION_KWARGS]
        return {"kind": "call", "callee": _flatten_callee(call.args[0]), "args": args, "line": line, "dispatch": f.attr}
    return None


def _lower_call_chain(node: ast.Call) -> dict[str, Any]:
    """Lowers a (possibly chained) call expression, e.g. `open(x).read()` or
    `a.b(x).c(y).d(z)`, WITHOUT losing an inner call's own arguments.

    _flatten_callee's "mixed shape" fallback (`func()[0].attr` -> just the
    last segment name) previously ALSO caught this shape — `.read` on a
    Call value is not an ast.Attribute-of-ast.Name chain, so it fell to
    that same fallback, which returns ONLY the bare terminal name and
    discards the entire inner Call node, including its arguments. Opening
    a path built from a tainted suffix and immediately reading it in one
    chained expression meant the tainted portion vanished completely — not
    just misattributed to the wrong arg index, but never represented in
    the IR at all. Confirmed via a real corpus fixture
    (CVE-2019-10097-python-path-traversal — see its pre/srv.py fixture for
    the exact disclosed shape this fixes).

    Walks the chain from the OUTERMOST call inward, collecting each level's
    (name segment, own args) — mirrors every hand-rolled parser's
    `_followChain` convention in this codebase: the reconstructed callee is
    the dot-joined names in SOURCE order (inner-to-outer, since we walked
    outer-to-inner), and the args are kept in OUTERMOST-FIRST order (a
    trailing no-arg call like `.read()` contributes nothing, so the
    innermost call's real argument — the tainted path — survives as
    `args[0]`, exactly where `argIndex: 0` catalog entries expect it).
    """
    segments: list[tuple[Any, list[dict[str, Any]]]] = []
    kwargs: dict[str, Any] = {}
    cur: Any = node
    while isinstance(cur, ast.Call):
        args = [_lower_expr(a) for a in (cur.args or [])]
        for kw in (cur.keywords or []):
            args.append(_lower_expr(kw.value))
            # Keyword NAMES were previously dropped: `subprocess.run(cmd,
            # shell=True)` lowered to args=[cmd, True] with no way to tell
            # which argument was `shell`. That made it impossible for a sink
            # to distinguish the shell-interpreted form from the safe
            # argv-array form, so py-subprocess-run fired on both and
            # labelled both "shell=True". Recorded alongside args rather than
            # instead of them, so every existing argIndex consumer is
            # unaffected. (PRD T3.1 prerequisite.)
            if kw.arg:
                kwargs.setdefault(kw.arg, _lower_expr(kw.value))
            else:
                # `**opts` — the keyword set is NOT enumerable here. Recorded
                # under a reserved key so a requireKeyword gate can tell
                # "this keyword is absent" from "we cannot see the keywords",
                # and stay recall-preserving in the second case.
                kwargs.setdefault("**", {"kind": "unknown"})
        func = cur.func
        if isinstance(func, ast.Attribute):
            segments.append((func.attr, args))
            cur = func.value
        elif isinstance(func, ast.Name):
            segments.append((func.id, args))
            cur = None
        else:
            # e.g. a subscript-returned callable (`handlers[key](x)`) —
            # no further name segment to extract; stop walking but keep
            # this level's own args.
            segments.append((None, args))
            cur = None
    prefix = _flatten_callee(cur) if cur is not None else None
    names = ([prefix] if prefix else []) + [s[0] for s in reversed(segments) if s[0]]
    callee = ".".join(names) if names else None
    all_args: list[dict[str, Any]] = []
    for _, args in segments:
        all_args = all_args + args
    call: dict[str, Any] = {"kind": "call", "callee": callee, "args": all_args}
    if kwargs:
        call["kwargs"] = kwargs
    inner = _inner_calls(node.func)
    if inner:
        call["innerCalls"] = inner
    return call


def _inner_calls(func: ast.AST) -> list[dict[str, Any]]:
    """The call a callee is built on, lowered on its own with its own arguments: `cur.execute(q).fetchall()` carries
    `cur.execute(q)`, `Template(s).render()` carries `Template(s)`, `a.b(x).c.d(y)` carries `a.b(x)`. The dotted callee
    and merged argument list above stay as they were (every consumer of them is unchanged); the engine reads
    `innerCalls` to give the inner call a sink site of its own, which the merged form cannot (the chain
    `obj.exec.run(x)` and the call chain `obj.exec().run(x)` flatten to the same string)."""
    cur: Any = func
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if not isinstance(cur, ast.Call):
        return []
    rec = _lower_call_chain(cur)
    rec["line"] = getattr(cur, "lineno", 0) or 0
    return [rec]


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
            # dispatch shape). For everything else, noop. `await f(x)` as a
            # statement is the call f(x): the await adds nothing the engine reads.
            val = stmt.value.value if isinstance(stmt.value, ast.Await) else stmt.value
            if isinstance(val, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                # `[os.system(c) for c in cmds]` as a statement: the loop variable is an element of the iterable and the head runs per element,
                # so the head call is a call node of its own (an assigned comprehension is handled below with its filters).
                tail = prev
                for gen in val.generators:
                    loop_tgt = _assign_target(gen.target)
                    if isinstance(loop_tgt, str):
                        la = self._add({"kind": "assign", "target": loop_tgt, "source": {"kind": "member", "object": _lower_expr(gen.iter), "prop": "[]"}, "line": line})
                        self._link(tail, la)
                        tail = la
                if isinstance(val.elt, ast.Call):
                    head = _lower_call_chain(val.elt)
                    head["line"] = line
                    cur = self._add(head)
                else:
                    cur = self._add({"kind": "noop", "line": line})
                self._link(tail, cur)
                return cur
            if isinstance(val, ast.Call):
                _node = {
                    "kind": "call",
                    "callee": _flatten_callee(val.func),
                    "args": [_lower_expr(a) for a in (val.args or [])]
                          + [_lower_expr(kw.value) for kw in (val.keywords or [])],
                    "line": line,
                }
                # Keyword names, so a sink can tell `subprocess.run(cmd,
                # shell=True)` from the safe argv-array form. See
                # _lower_call_chain for the full rationale.
                _kw = {kw.arg: _lower_expr(kw.value) for kw in (val.keywords or []) if kw.arg}
                if any(kw.arg is None for kw in (val.keywords or [])):
                    _kw["**"] = {"kind": "unknown"}   # see _lower_call_chain
                if _kw:
                    _node["kwargs"] = _kw
                _inner = _inner_calls(val.func)
                if _inner:
                    _node["innerCalls"] = _inner
                cur = self._add(_node)
                _d = _dispatch_call(val, line)
                if _d:
                    self._link(prev, cur)
                    prev = cur
                    cur = self._add(_d)
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
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Subscript):
            # Taint-recall PRD (80%): `response["X-Trace"] = tainted` / a
            # subscript-assignment target. `_assign_target` has no branch for
            # ast.Subscript, so this previously fell through to `target: None`
            # — an untracked, effectively no-op assign; the write itself was
            # invisible to every sink check (matchMemberWriteSink needs a
            # dotted `target` string; the RHS-is-a-call check doesn't apply
            # since the RHS here is rarely a call). Lowered instead as a
            # synthetic `<receiver>.__setitem__(key, value)` call so it flows
            # through the SAME argument-based sink-matching machinery every
            # other call already uses — no new engine mechanism, argIndex 1
            # for the value. `d[k] = v` for an ordinary dict still produces
            # this same shape; it's harmless (no catalog entry matches
            # '__setitem__' without a receiver constraint, so it resolves as
            # an ordinary unrecognized call, same effective no-op as before).
            receiver = _flatten_callee(stmt.targets[0].value)
            key_expr = _lower_expr(stmt.targets[0].slice)
            cur = self._add({
                "kind": "call",
                "callee": f"{receiver}.__setitem__" if receiver else "__setitem__",
                "args": [key_expr, _lower_expr(stmt.value)],
                "line": line,
            })
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
            node_rec: dict[str, Any] = {"kind": "assign", "target": tgt, "source": src, "line": line}
            # The declared or constructed type of a plain local (`s: Service = ...`, `s = Service()`), for
            # receiver typing; a container or library name matches no project class and is inert.
            if isinstance(tgt, str) and isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                dt = _annotation_name(stmt.annotation) if isinstance(stmt, ast.AnnAssign) else None
                if not dt:
                    dt = _ctor_class_name(stmt.value)
                if dt:
                    node_rec["declaredType"] = dt
            cur = self._add(node_rec)
            _d = _dispatch_call(stmt.value, line) if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) else None
            if _d:
                self._link(prev, cur)
                prev = cur
                cur = self._add(_d)
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
                    rec = {
                        "kind": "assign", "target": tgt,
                        "source": _lower_expr(item.context_expr), "line": line,
                    }
                    # `with httpx.Client() as c`: the bound name is the constructed object (its __enter__ returns self for
                    # clients, sessions and connections), so the receiver type is known as for a plain assignment.
                    dt = _ctor_class_name(item.context_expr)
                    if dt:
                        rec["declaredType"] = dt
                    a = self._add(rec)
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


def _annotation_name(ann: Any) -> "str | None":
    """The simple class name a type annotation names: `Service`, `pkg.Service`, `"Service"`,
    `Optional[Service]`. Containers keep their own name (`list`), which no project class matches."""
    if ann is None:
        return None
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Attribute):
        return ann.attr
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return ann.value.split(".")[-1] or None
    if isinstance(ann, ast.Subscript):
        base = _annotation_name(ann.value)
        if base in ("Optional", "Union", "Annotated", "Final", "ClassVar"):
            sl = ann.slice
            if isinstance(sl, ast.Tuple) and sl.elts:
                return _annotation_name(sl.elts[0])
            return _annotation_name(sl)
        return base
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        return _annotation_name(ann.left)
    return None


def _ctor_class_name(value: Any) -> "str | None":
    """`Service()` / `pkg.Service(...)`: a capitalised callee is a constructor by Python convention. The class
    hierarchy only honours a name that is a class of the project, so a library name resolves to nothing."""
    if not isinstance(value, ast.Call):
        return None
    f = value.func
    nm = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
    if nm and nm[:1].isupper() and not nm.isupper():
        return nm
    return None


def _param_types(node: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    args = node.args
    for a in list(getattr(args, "posonlyargs", [])) + list(args.args) + list(args.kwonlyargs):
        if a.arg in ("self", "cls"):
            continue
        t = _annotation_name(a.annotation)
        if t:
            out[a.arg] = t
    return out


def _extract_classes(tree: ast.Module, file: str) -> list[dict[str, Any]]:
    """One record per class: name, bases, the instance and class attributes it assigns, and the declared or
    constructed type of each where one is visible (`self.svc = Service()`, `self.svc = svc` with `svc: Service`
    in the signature, `svc: Service = ...`). The IR states the facts; class-hierarchy.js types receivers from them."""
    out: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases: list[str] = []
        for b in node.bases:
            nm = b.id if isinstance(b, ast.Name) else (b.attr if isinstance(b, ast.Attribute) else None)
            if nm:
                bases.append(nm)
        fields: list[str] = []
        field_types: dict[str, str] = {}

        def note(name: str, t: "str | None") -> None:
            if name not in fields:
                fields.append(name)
            if t and name not in field_types:
                field_types[name] = t

        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for tg in stmt.targets:
                    if isinstance(tg, ast.Name):
                        note(tg.id, _ctor_class_name(stmt.value))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                note(stmt.target.id, _annotation_name(stmt.annotation) or _ctor_class_name(stmt.value))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ptypes = _param_types(stmt)
                for sub in ast.walk(stmt):
                    pairs: list[tuple[Any, Any, Any]] = []
                    if isinstance(sub, ast.Assign):
                        pairs = [(tg, sub.value, None) for tg in sub.targets]
                    elif isinstance(sub, ast.AnnAssign):
                        pairs = [(sub.target, sub.value, sub.annotation)]
                    for tg, val, ann in pairs:
                        if isinstance(tg, ast.Attribute) and isinstance(tg.value, ast.Name) and tg.value.id == "self":
                            t = _annotation_name(ann) if ann is not None else None
                            if not t:
                                t = _ctor_class_name(val)
                            if not t and isinstance(val, ast.Name):
                                t = ptypes.get(val.id)
                            note(tg.attr, t)
        rec: dict[str, Any] = {"name": node.name, "line": node.lineno or 0, "bases": bases, "fields": fields}
        if field_types:
            rec["fieldTypes"] = field_types
        out.append(rec)
    return out


def _extract_functions(tree: ast.Module, file: str) -> list[dict[str, Any]]:
    """Walk the module, capturing every function (top-level, nested, or a method) into a flat list with its
    enclosing class when it has one. Each function's body is lowered into a CFG."""
    fns: list[dict[str, Any]] = []
    dependency_targets = _dependency_targets(tree)

    def visit(parent: Any, cls: "str | None", bases: "list[str] | None") -> None:
        for child in ast.iter_child_nodes(parent):
            if isinstance(child, ast.ClassDef):
                visit(child, child.name, _base_names(child))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fns.append(_function_record(child, file, cls, child.name in dependency_targets, bases))
                visit(child, None, None)
            elif isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name) and isinstance(child.value, ast.Lambda):
                # `f = lambda h: run(h)`: a function named f with the lambda's parameters and a single return, so a later `f(x)`
                # resolves to it and its body is analysed with x.
                lam = child.value
                fd = ast.FunctionDef(name=child.targets[0].id, args=lam.args, body=[ast.Return(value=lam.body)], decorator_list=[], returns=None)
                if hasattr(fd, "type_params"):
                    fd.type_params = []
                ast.copy_location(fd, child)
                ast.fix_missing_locations(fd)
                fns.append(_function_record(fd, file, cls, False, bases))
                visit(child, cls, bases)
            else:
                visit(child, cls, bases)

    visit(tree, None, None)
    return fns


def _base_names(node: ast.ClassDef) -> list[str]:
    out: list[str] = []
    for b in node.bases:
        nm = b.id if isinstance(b, ast.Name) else (b.attr if isinstance(b, ast.Attribute) else None)
        if nm:
            out.append(nm)
    return out


_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "trace", "dispatch"}
_VIEW_LIKE_RE = re.compile(r"(?:View|ViewSet|Mixin)$")


def _is_view_class(bases: "list[str] | None") -> bool:
    """A Django or DRF class-based view: a base named like a view (View, TemplateView, APIView, ModelViewSet, ...). The URL captures
    reach it as the method's extra parameters and as self.kwargs."""
    return bool(bases) and any(_VIEW_LIKE_RE.search(b) for b in bases)


def _class_param_annotations(node: Any, params: list[str], bases: "list[str] | None") -> list[dict[str, Any]]:
    """Request-filled parameters a class's base decides: a gRPC servicer method's `request`, a graphene resolver's arguments
    after (self, info), a Django view method's URL captures after (self, request). The IR states the fact; the catalog names the source."""
    out: list[dict[str, Any]] = []
    if not bases:
        return out
    name = node.name
    if any(b.endswith("Servicer") for b in bases) and len(params) >= 2 and params[1] == "request":
        out.append({"index": 1, "name": "request", "decorator": "py:grpc-request"})
    if name.startswith("resolve_") and len(params) >= 2 and params[1] == "info":
        for i, p in enumerate(params[2:], start=2):
            out.append({"index": i, "name": p, "decorator": "py:graphql-resolver-arg"})
    if _is_view_class(bases) and name in _HTTP_VERBS and len(params) >= 2:
        vararg = node.args.vararg.arg if node.args.vararg else None
        for i, p in enumerate(params[2:], start=2):
            if p == vararg:
                continue
            out.append({"index": i, "name": p, "decorator": "py:django-view-kwarg"})
    return out


def _dependency_targets(tree: ast.Module) -> set[str]:
    """Names of the functions referenced as `Depends(fn)` / `Security(fn)` defaults anywhere in the module. FastAPI
    fills such a function's own parameters from the request exactly as it fills a route handler's, so they are
    marked as route parameters below even though the function carries no route decorator."""
    out: set[str] = set()
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in list(n.args.defaults) + [k for k in n.args.kw_defaults if k is not None]:
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("Depends", "Security") and d.args and isinstance(d.args[0], ast.Name):
                out.add(d.args[0].id)
    return out


def _dependency_assigns(node: Any) -> list[ast.stmt]:
    """`name: str = Depends(get_name)` binds the parameter to the dependency's return value: stated as `name = get_name()`
    at the top of the body, so the engine resolves the callee and reads its return taint. `Depends()` with no target
    (a class dependency from the annotation) states nothing."""
    out: list[ast.stmt] = []
    args = node.args
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    pos_defaults = list(args.defaults)
    offset = len(positional) - len(pos_defaults)
    pairs = [(positional[offset + i], d) for i, d in enumerate(pos_defaults) if 0 <= offset + i < len(positional)]
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    for arg, d in pairs:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("Depends", "Security") and d.args and isinstance(d.args[0], ast.Name):
            call = ast.Call(func=ast.Name(id=d.args[0].id, ctx=ast.Load()), args=[], keywords=[])
            stmt = ast.Assign(targets=[ast.Name(id=arg.arg, ctx=ast.Store())], value=call)
            for x in ast.walk(stmt):
                x.lineno = node.lineno or 0
                x.col_offset = 0
                x.end_lineno = node.lineno or 0
                x.end_col_offset = 0
            out.append(stmt)
    return out


def _function_record(node: Any, file: str, cls: "str | None", dependency_target: bool = False, bases: "list[str] | None" = None) -> dict[str, Any]:
    if True:
        params = [a.arg for a in node.args.args]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        if node.args.kwarg:
            params.append(node.args.kwarg.arg)
        for a in node.args.kwonlyargs:
            params.append(a.arg)
        line = node.lineno or 0
        builder = CfgBuilder(node.name)
        _LOWER_CTX["view_class"] = _is_view_class(bases)
        try:
            builder.lower(_dependency_assigns(node) + list(node.body))
        finally:
            _LOWER_CTX["view_class"] = False
        # A method's qid carries its class (`file::Class::method@line#hash`), the shape class-hierarchy.js and
        # callgraph.js read class membership from for Java and C#; `name` stays the bare name every Python
        # consumer matches on.
        fn_rec = {
            "qid": _qid(file, f"{cls}::{node.name}" if cls else node.name, line),
            "name": node.name,
            "line": line,
            "params": params,
            "file": file,
            "cfg": {
                "entry": builder.entry,
                "exit": builder.exit,
                "nodes": builder.nodes,
            },
        }
        if cls:
            fn_rec["className"] = cls
        ptypes = _param_types(node)
        if ptypes:
            fn_rec["paramTypes"] = ptypes
        pa = _param_annotations(node, params) + _class_param_annotations(node, params, bases)
        if dependency_target:
            pa = pa + _route_params(node, params, assume_route=True)
        if pa:
            fn_rec["paramAnnotations"] = pa
        if getattr(node, "returns", None) is not None:
            rt = _annotation_name(node.returns)
            if rt:
                fn_rec["returnType"] = rt
        # A view registered with `@<app|bp>.route("/...")` (Flask, Quart, Bottle) sends a returned str as
        # text/html, so each of its returns is a response write. Marked on the return node; the engine reads it
        # as a sink call only when the returned text carries markup. The verb decorators (`@app.get`) are
        # left out: FastAPI uses the same spelling and JSON-encodes a returned str.
        if _is_html_view(node):
            for n in builder.nodes.values():
                if n.get("kind") == "return" and n.get("value") is not None:
                    n["routeReturn"] = True
        return fn_rec


def _decorator_names(node: Any) -> list[str]:
    """Every decorator on a function, as both its dotted form and its last
    segment.

    Both are emitted because the receiver of a decorator is a local naming
    choice — `@mcp.tool()`, `@server.tool()` and `@app.tool()` are the same
    framework concept — while the last segment alone (`tool`) is too generic
    to key a taint source on by itself. Emitting both lets the catalog choose
    how specific it wants to be, and costs nothing when it matches neither.
    """
    out: list[str] = []
    for d in getattr(node, "decorator_list", []) or []:
        expr = d.func if isinstance(d, ast.Call) else d
        parts: list[str] = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if isinstance(expr, ast.Name):
            parts.append(expr.id)
        if not parts:
            continue
        parts.reverse()
        dotted = ".".join(parts)
        out.append(dotted)
        if len(parts) > 1:
            out.append(parts[-1])
    return out


def _param_annotations(node: Any, params: list[str]) -> list[dict[str, Any]]:
    """Entry-point markers on a function's parameters, in the IR's shared
    `{index, name, decorator}` side-channel shape (see ir/CLAUDE.md).

    Python expresses "this parameter is attacker-controlled" two ways, and both
    are captured here:

      1. A FUNCTION-level decorator that makes the whole function an entry
         point — `@mcp.tool()`, `@app.route(...)`, `@celery.task`. Every
         parameter inherits it.
      2. A PER-PARAMETER default marker — FastAPI's
         `q: str = Query(...)` / `Body(...)` / `Form(...)` / `Header(...)`.

    Nothing is decided here about which of these is untrusted. The IR emits the
    fact that the decorator exists; dataflow/catalog.js decides whether it
    names a source, exactly as it already does for Java/C#/NestJS. That
    separation is why emitting broadly is safe: an unrecognised decorator
    (`@staticmethod`, `@lru_cache`) resolves to no catalog entry and therefore
    to no taint.
    """
    out: list[dict[str, Any]] = []

    for dec in _decorator_names(node):
        for idx, pname in enumerate(params):
            if pname in ("self", "cls"):
                continue
            out.append({"index": idx, "name": pname, "decorator": dec})

    # Per-parameter markers: the default value is a call, e.g. `= Query(...)`.
    args = node.args
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    defaults = list(args.defaults)
    # `defaults` right-aligns with the positional parameters.
    offset = len(positional) - len(defaults)
    pairs = [(positional[offset + i], d) for i, d in enumerate(defaults) if 0 <= offset + i < len(positional)]
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    for arg, default in pairs:
        expr = default.func if isinstance(default, ast.Call) else default
        marker = None
        if isinstance(expr, ast.Name):
            marker = expr.id
        elif isinstance(expr, ast.Attribute):
            marker = expr.attr
        if not marker:
            continue
        try:
            idx = params.index(arg.arg)
        except ValueError:
            continue
        out.append({"index": idx, "name": arg.arg, "decorator": marker})

    out.extend(_route_params(node, params))
    return out


# Route decorators whose handler parameters the framework fills from the
# request: Flask/Quart/Bottle `@app.route("/p/<x>")`, FastAPI/Starlette/
# Flask 2 `@app.get("/p/{x}")` and friends, `@app.api_route(...)`.
_ROUTE_DECORATOR_ATTRS = {"route", "get", "post", "put", "patch", "delete", "api_route"}
# A parameter whose annotation is one of these cannot carry an injection
# payload (the framework converts or rejects the value).
_NON_TEXT_ANNOTATIONS = {"int", "float", "bool", "UUID", "uuid", "datetime", "date", "time", "Decimal", "PositiveInt", "NonNegativeInt", "conint", "confloat"}
# Default-value markers that make a parameter dependency-injected or
# framework-provided rather than request text.
_INJECTED_DEFAULTS = {"Depends", "Security", "BackgroundTasks"}
# Annotations naming framework objects that are injected, not parsed from the request.
_INJECTED_ANNOTATIONS = {"BackgroundTasks", "Response", "WebSocket", "Session", "AsyncSession", "HTTPConnection"}
# Flask/Werkzeug route converters that only admit non-text values.
_NUMERIC_CONVERTER_RE = re.compile(r"<(?:int|float|uuid):(\w+)>")


def _annotation_name(ann: Any) -> Optional[str]:
    """Last name of a parameter annotation, unwrapping Optional[...] and
    Annotated[T, ...] to T; None when the annotation is absent or complex."""
    while isinstance(ann, ast.Subscript):
        base = ann.value
        base_name = base.attr if isinstance(base, ast.Attribute) else (base.id if isinstance(base, ast.Name) else None)
        if base_name not in ("Optional", "Annotated"):
            return base_name
        inner = ann.slice
        if isinstance(inner, ast.Tuple) and inner.elts:
            inner = inner.elts[0]
        ann = inner
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Attribute):
        return ann.attr
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        return ann.value.split("[")[0].split(".")[-1]
    return None


def _is_html_view(node: Any) -> bool:
    """True for a function decorated with `@<x>.route("/literal-path")`."""
    for d in getattr(node, "decorator_list", []) or []:
        if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute) or d.func.attr != "route" or not d.args:
            continue
        first = d.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.startswith("/"):
            return True
    return False


def _route_params(node: Any, params: list[str], assume_route: bool = False) -> list[dict[str, Any]]:
    """`py:route-param` markers for the parameters of a web route handler.

    Only a decorator CALL whose attribute is a route verb and whose first
    argument is a literal path beginning with "/" counts, so `@cache.get`,
    `@property` and a bare `@app.get` without a path never mark anything. A
    parameter is skipped when it is annotated with a non-text type, when its
    default is a dependency-injection marker, when its annotation names an
    injected framework object, or when the route path binds it with a
    numeric converter (`<int:id>`)."""
    route_paths: list[str] = []
    for d in getattr(node, "decorator_list", []) or []:
        if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute):
            continue
        if d.func.attr not in _ROUTE_DECORATOR_ATTRS or not d.args:
            continue
        first = d.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.startswith("/"):
            route_paths.append(first.value)
    if not route_paths and not assume_route:
        return []
    numeric = set()
    for p in route_paths:
        numeric.update(_NUMERIC_CONVERTER_RE.findall(p))
    args = node.args
    positional = list(getattr(args, "posonlyargs", [])) + list(args.args)
    all_args = positional + list(args.kwonlyargs)
    defaults: dict[str, Any] = {}
    pos_defaults = list(args.defaults)
    offset = len(positional) - len(pos_defaults)
    for i, dflt in enumerate(pos_defaults):
        if 0 <= offset + i < len(positional):
            defaults[positional[offset + i].arg] = dflt
    for a, dflt in zip(args.kwonlyargs, args.kw_defaults):
        if dflt is not None:
            defaults[a.arg] = dflt
    out: list[dict[str, Any]] = []
    for a in all_args:
        name = a.arg
        if name in ("self", "cls") or name in numeric:
            continue
        ann = _annotation_name(a.annotation) if a.annotation is not None else None
        if ann in _NON_TEXT_ANNOTATIONS or ann in _INJECTED_ANNOTATIONS:
            continue
        dflt = defaults.get(name)
        if dflt is not None:
            f = dflt.func if isinstance(dflt, ast.Call) else dflt
            marker = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if marker in _INJECTED_DEFAULTS:
                continue
            # A non-string literal default (`page=1`, `flag=False`) means a numeric/boolean query parameter.
            if isinstance(dflt, ast.Constant) and not isinstance(dflt.value, str) and dflt.value is not None:
                continue
        try:
            idx = params.index(name)
        except ValueError:
            continue
        out.append({"index": idx, "name": name, "decorator": "py:route-param"})
    return out


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
    rec = {"file": file, "functions": fns, "classes": _extract_classes(tree, file), "topLevel": top_level_qid}
    caps = _url_captures(tree)
    if caps:
        rec["urlCaptures"] = caps
    return rec


_PATH_CAPTURE_RE = re.compile(r"<(?:(\w+):)?(\w+)>")
_RE_GROUP_RE = re.compile(r"\(\?P<(\w+)>((?:[^()]|\([^()]*\))*)\)")
_TEXT_CONVERTERS = {None, "str", "slug", "path"}


def _url_captures(tree: ast.Module) -> list[dict[str, Any]]:
    """Django URL routes: `path("a/<name>/", views.v)`, `re_path(r"^a/(?P<name>\\w+)/$", v)` and the old `url(...)`. Each
    gives the view's name (and its module when written `views.v`) with the text captures of the route; numeric and
    uuid converters and digit-only groups are left out. A class-based `V.as_view()` is not a function and is skipped.
    The IR states the route facts; ir/index.js links them to the view's parameters."""
    out: list[dict[str, Any]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or len(n.args) < 2:
            continue
        f = n.func
        fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if fname not in ("path", "re_path", "url"):
            continue
        route, view = n.args[0], n.args[1]
        if not (isinstance(route, ast.Constant) and isinstance(route.value, str)):
            continue
        if isinstance(view, ast.Name):
            vname, module = view.id, None
        elif isinstance(view, ast.Attribute) and isinstance(view.value, ast.Name):
            vname, module = view.attr, view.value.id
        else:
            continue
        names: list[str] = []
        if fname == "path":
            for conv, nm in _PATH_CAPTURE_RE.findall(route.value):
                if (conv or None) in _TEXT_CONVERTERS and nm not in names:
                    names.append(nm)
        else:
            for nm, pat in _RE_GROUP_RE.findall(route.value):
                if not re.search(r"\\d|\[0-9|\[\\d", pat) and nm not in names:
                    names.append(nm)
        if names:
            out.append({"view": vname, "module": module, "params": names, "line": n.lineno or 0})
    return out


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
