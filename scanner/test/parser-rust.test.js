// Rust IR frontend: CFG shape tests.
//
// Rust previously had no Layer-1 IR at all (only the opt-in tree-sitter
// long-tail path, which nothing in the taint engine consumes), so every
// `.rs` file was invisible to Layer-2 taint. These pin the shapes the
// hand-rolled parser must produce for the engine contract in ir/CLAUDE.md.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRustFile } from '../src/ir/parser-rust.js';

function nodesOf(ir, name) {
  const fn = ir.functions.find(f => f.name === name);
  assert.ok(fn, `expected function ${name}, got: ${ir.functions.map(f => f.name).join(', ')}`);
  return { fn, nodes: Object.values(fn.cfg.nodes) };
}

test('parseRustFile: refuses non-.rs files and empty input', () => {
  assert.equal(parseRustFile('main.go', 'fn x() {}'), null);
  assert.equal(parseRustFile('main.rs', ''), null);
});

test('parseRustFile: fn header with qualifiers, generics, return type; let + call', () => {
  const code = `use std::process::Command;

pub async fn handler<T: Into<String>>(user: &str, n: T) -> Result<String, Box<dyn Error>> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(user);
    let out = cmd.output()?;
    Ok(String::from_utf8(out.stdout)?)
}
`;
  const ir = parseRustFile('main.rs', code);
  assert.ok(ir);
  const { fn, nodes } = nodesOf(ir, 'handler');
  assert.equal(fn.line, 3);
  assert.deepEqual(fn.params, ['user', 'n']);
  const assigns = nodes.filter(n => n.kind === 'assign');
  const cmd = assigns.find(a => a.target === 'cmd');
  assert.ok(cmd, 'let mut cmd = ... must lower to an assign');
  assert.equal(cmd.source.kind, 'call');
  assert.equal(cmd.source.callee, 'Command.new', ':: paths normalize to dots');
  assert.equal(cmd.line, 4);
  const calls = nodes.filter(n => n.kind === 'call');
  const chain = calls.find(c => c.callee === 'cmd.arg.arg');
  assert.ok(chain, `chained call must dot-join, got: ${calls.map(c => c.callee).join(', ')}`);
  assert.deepEqual(chain.args.map(a => a.kind === 'literal' ? a.value : a.name), ['"-c"', 'user'],
    'chain args accumulate innermost-first (source order)');
  const out = assigns.find(a => a.target === 'out');
  assert.equal(out.source.callee, 'cmd.output', '? operator is stripped');
  const ret = nodes.find(n => n.kind === 'return');
  assert.ok(ret, 'tail expression without ; is the return value');
  assert.equal(ret.value.kind, 'call');
  assert.equal(ret.value.callee, 'Ok');
});

test('parseRustFile: impl methods are class-qualified and self is a param', () => {
  const code = `struct Repo { pool: Pool }

impl Repo {
    pub fn find(&self, id: &str) -> Vec<Row> {
        let sql = format!("SELECT * FROM t WHERE id = '{}'", id);
        self.pool.query(&sql)
    }
}

impl Display for Repo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result { write!(f, "repo") }
}

fn free() {}
`;
  const ir = parseRustFile('repo.rs', code);
  const names = ir.functions.map(f => f.name);
  assert.ok(names.includes('Repo.find'), names.join(','));
  assert.ok(names.includes('Repo.fmt'), 'impl Trait for Type qualifies by Type');
  assert.ok(names.includes('free'));
  const { fn, nodes } = nodesOf(ir, 'Repo.find');
  assert.deepEqual(fn.params, ['self', 'id']);
  const sql = nodes.find(n => n.kind === 'assign' && n.target === 'sql');
  assert.equal(sql.source.kind, 'tpl', 'format! lowers to a template');
  assert.ok(sql.source.parts.some(p => p.kind === 'ident' && p.name === 'id'), 'positional format arg is a part');
  const ret = nodes.find(n => n.kind === 'return');
  assert.equal(ret.value.callee, 'self.pool.query');
  assert.equal(ret.value.args[0].kind, 'ident');
  assert.equal(ret.value.args[0].name, 'sql', '& is stripped from the argument');
});

test('parseRustFile: format! inline {ident} args, write! drops the writer, vec! is an array', () => {
  const code = `fn f(name: &str, w: &mut String) {
    let a = format!("hello {name}!");
    let b = format!("{name:?} {}", 42);
    let c = format!("{0} {1}", name, w);
    write!(w, "x = {}", name).unwrap();
    let v = vec![name, "y"];
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const a = nodes.find(n => n.target === 'a').source;
  assert.equal(a.kind, 'tpl');
  assert.ok(a.parts.some(p => p.kind === 'ident' && p.name === 'name'), 'inline {name} is captured');
  const b = nodes.find(n => n.target === 'b').source;
  assert.ok(b.parts.some(p => p.kind === 'ident' && p.name === 'name'), 'inline {name:?} is captured');
  const c = nodes.find(n => n.target === 'c').source;
  assert.equal(c.parts.filter(p => p.kind === 'ident').length, 2);
  const wr = nodes.find(n => n.kind === 'call' && /write!/.test(String(n.callee)));
  assert.ok(wr, 'write! statement is a call node');
  assert.ok(!wr.args.some(p => p.kind === 'ident' && p.name === 'w'), 'the writer is not a template part');
  const v = nodes.find(n => n.target === 'v').source;
  assert.equal(v.kind, 'array');
  assert.equal(v.elements.length, 2);
});

test('parseRustFile: sqlx::query! (bang) keeps its bang so it never matches the query sink', () => {
  const code = `async fn f(id: &str, pool: &Pool) {
    let r = sqlx::query!("SELECT * FROM t WHERE id = $1", id).fetch_one(pool).await;
    let s = sqlx::query(&format!("SELECT * FROM t WHERE id = '{}'", id)).fetch_one(pool).await;
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const r = nodes.find(n => n.target === 'r').source;
  assert.equal(r.kind, 'call');
  assert.equal(r.callee, 'sqlx.query!.fetch_one');
  const s = nodes.find(n => n.target === 's').source;
  assert.equal(s.callee, 'sqlx.query.fetch_one', '.await is stripped');
  assert.equal(s.args[0].kind, 'tpl');
});

test('parseRustFile: control flow bodies are real CFG nodes (if/else if/while/loop/for/match/unsafe)', () => {
  const code = `fn f(x: &str, xs: Vec<String>) {
    if x.is_empty() {
        sink1(x);
    } else if x.len() > 3 {
        sink2(x);
    } else {
        sink3(x);
    }
    while cond() {
        sink4(x);
    }
    loop {
        sink5(x);
        break;
    }
    for item in xs {
        sink6(item);
    }
    match x.parse::<i64>() {
        Ok(n) => sink7(n),
        Err(e) => { sink8(e); }
    }
    unsafe { sink9(x); }
    { sink10(x); }
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const callees = nodes.filter(n => n.kind === 'call').map(n => n.callee);
  for (let i = 1; i <= 10; i++) assert.ok(callees.includes(`sink${i}`), `sink${i} missing from ${callees.join(', ')}`);
  const forAssign = nodes.find(n => n.kind === 'assign' && n.target === 'item');
  assert.ok(forAssign, 'for loop binds its variable to the iterated expression');
  assert.equal(forAssign.source.kind, 'ident');
  assert.equal(forAssign.source.name, 'xs');
  const nBind = nodes.find(n => n.kind === 'assign' && n.target === 'n');
  assert.ok(nBind, 'match arm pattern binds n to the scrutinee');
  assert.equal(nBind.source.callee, 'x.parse', 'turbofish is stripped');
  assert.ok(nodes.some(n => n.kind === 'loop-header'));
  assert.ok(nodes.filter(n => n.kind === 'if').length >= 2);
  const s7 = nodes.find(n => n.kind === 'call' && n.callee === 'sink7');
  assert.equal(s7.line, 20);
  const s10 = nodes.find(n => n.kind === 'call' && n.callee === 'sink10');
  assert.equal(s10.line, 24);
});

test('parseRustFile: if let / while let bind the pattern; let-expression control flow yields a union', () => {
  const code = `fn f(opt: Option<String>, q: &str) {
    if let Some(v) = opt {
        sink(v);
    }
    while let Some(line) = reader.next() {
        sink(line);
    }
    let s = if q.is_empty() { String::new() } else { format!("{}", q) };
    let t = match opt { Some(x) => x, None => String::new() };
    use_it(s, t);
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const v = nodes.find(n => n.kind === 'assign' && n.target === 'v');
  assert.ok(v && v.source.name === 'opt');
  const line = nodes.find(n => n.kind === 'assign' && n.target === 'line');
  assert.ok(line && line.source.callee === 'reader.next');
  const s = nodes.find(n => n.kind === 'assign' && n.target === 's');
  assert.ok(s, 'let s = if … lowers to an assign');
  assert.equal(s.source.kind, 'union');
  assert.ok(s.source.branches.some(b => b.kind === 'tpl'), 'the else branch tail is a branch');
  const t = nodes.find(n => n.kind === 'assign' && n.target === 't');
  assert.equal(t.source.kind, 'union');
  assert.ok(t.source.branches.some(b => b.kind === 'ident' && b.name === 'x'));
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === 'x' && n.source.name === 'opt'));
});

test('parseRustFile: trailing closures are inlined with their parameter bound to the receiver', () => {
  const code = `fn f(names: Vec<String>) {
    names.iter().for_each(|n| {
        sink(n);
    });
    names.iter().map(|n| format!("<{n}>")).collect::<Vec<_>>();
    std::thread::spawn(move || {
        sink2(names);
    });
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const bind = nodes.find(n => n.kind === 'assign' && n.target === 'n');
  assert.ok(bind, 'closure param n is bound');
  assert.equal(bind.source.kind, 'member');
  assert.equal(bind.source.object.name, 'names');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'sink'), 'closure body statement is a CFG node');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'sink2'), 'move closure body is a CFG node');
  const forEach = nodes.find(n => n.kind === 'call' && n.callee === 'names.iter.for_each');
  assert.ok(forEach, 'the registration call itself is kept');
  assert.equal(forEach.args.length, 0, 'the closure is not passed as an opaque arg');
});

test('parseRustFile: string concat +, push_str, += and index writes', () => {
  const code = `fn f(q: &str) {
    let mut s = "SELECT ".to_string() + q + " FROM t";
    s.push_str(q);
    s += q;
    let mut m = HashMap::new();
    m["k"] = q;
    s = s.trim().to_lowercase() as String;
}
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  const s0 = nodes.find(n => n.kind === 'assign' && n.target === 's');
  assert.equal(s0.source.kind, 'tpl');
  assert.ok(s0.source.parts.some(p => p.kind === 'ident' && p.name === 'q'));
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 's.push_str'));
  const plusEq = nodes.filter(n => n.kind === 'assign' && n.target === 's')[1];
  assert.equal(plusEq.source.kind, 'tpl', '+= is a template of the old value and the rhs');
  const setitem = nodes.find(n => n.kind === 'call' && n.callee === 'm.__setitem__');
  assert.ok(setitem, 'index write lowers to the __setitem__ mutator');
  const cast = nodes.filter(n => n.kind === 'assign' && n.target === 's')[2];
  assert.equal(cast.source.callee, 's.trim.to_lowercase', 'as-cast is stripped');
});

test('parseRustFile: raw strings, byte strings, char literals and nested comments do not corrupt the body', () => {
  const code = `fn f(q: &str) {
    let re = r#"a "quoted" {brace}"#; /* outer /* inner } */ still comment */
    let c = '{'; let d = b'}'; let lt: &'static str = "x"; // trailing } brace
    let e = format!("{{literal}} {}", q);
    sink(q);
}

fn g() { after(); }
`;
  const ir = parseRustFile('f.rs', code);
  const { nodes } = nodesOf(ir, 'f');
  assert.ok(nodes.some(n => n.kind === 'call' && n.callee === 'sink'));
  const e = nodes.find(n => n.kind === 'assign' && n.target === 'e').source;
  assert.equal(e.kind, 'tpl');
  assert.equal(e.parts.filter(p => p.kind === 'ident').length, 1, '{{ }} escapes are not placeholders');
  assert.ok(ir.functions.some(f => f.name === 'g'), 'the next function is still found');
});

test('parseRustFile: extractor-typed params emit paramAnnotations; route attributes mark plain params', () => {
  const code = `#[get("/user/<name>?<page>")]
fn user(name: &str, page: Option<u32>, db: &State<Db>) -> String { name.to_string() }

async fn search(Query(params): Query<SearchParams>, Path((a, b)): Path<(String, u32)>, headers: HeaderMap, body: web::Json<Body>) {}
`;
  const ir = parseRustFile('f.rs', code);
  const user = ir.functions.find(f => f.name === 'user');
  assert.deepEqual(user.params, ['name', 'page', 'db']);
  assert.ok(user.paramAnnotations.some(a => a.name === 'name' && a.decorator === 'RouteParam'));
  assert.ok(user.paramAnnotations.some(a => a.name === 'page' && a.decorator === 'RouteParam'));
  const search = ir.functions.find(f => f.name === 'search');
  assert.deepEqual(search.params, ['params', 'a', 'b', 'headers', 'body']);
  const deco = Object.fromEntries(search.paramAnnotations.map(a => [a.name, a.decorator]));
  assert.equal(deco.params, 'Query');
  assert.equal(deco.a, 'Path');
  assert.equal(deco.b, 'Path');
  assert.equal(deco.headers, 'HeaderMap');
  assert.equal(deco.body, 'Json');
});

test('parseRustFile: fn.calls is populated from the CFG', () => {
  const ir = parseRustFile('f.rs', `fn f(x: &str) { let y = helper(x); sink(y); }\nfn helper(a: &str) -> String { a.to_string() }`);
  const f = ir.functions.find(fn => fn.name === 'f');
  assert.ok(f.calls.some(c => c.callee === 'helper'));
  assert.ok(f.calls.some(c => c.callee === 'sink'));
});
