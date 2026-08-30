import { accessPathOf } from '../dataflow/access-paths.js';
import { identitiesAt } from './field-identity.js';

function noIdentity() {
  return { flat: new Set(), byPath: new Map(), widened: false };
}

export function resolveExprIdentities(state, expr) {
  if (!expr) return noIdentity();

  switch (expr.kind) {
    case 'ident':
    case 'member': {
      const path = accessPathOf(expr);
      return { flat: path ? identitiesAt(state, path) : new Set(), byPath: new Map(), widened: false };
    }

    case 'literal':
    case 'unknown':
      return noIdentity();

    case 'object': {
      const flat = new Set();
      const byPath = new Map();
      for (const prop of expr.props) {
        const r = resolveExprIdentities(state, prop.value);
        for (const id of r.flat) flat.add(id);
        if (r.flat.size > 0) {
          const existing = byPath.get(prop.key) ?? new Set();
          byPath.set(prop.key, new Set([...existing, ...r.flat]));
        }
        for (const [subPath, ids] of r.byPath) {
          const fullPath = `${prop.key}.${subPath}`;
          const existing = byPath.get(fullPath) ?? new Set();
          byPath.set(fullPath, new Set([...existing, ...ids]));
        }
      }
      return { flat, byPath, widened: false };
    }

    case 'array': {
      const flat = new Set();
      for (const el of expr.elements) {
        const r = resolveExprIdentities(state, el);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'tpl': {
      const flat = new Set();
      for (const part of expr.parts) {
        const r = resolveExprIdentities(state, part);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'binary':
    case 'logical': {
      const left = resolveExprIdentities(state, expr.left);
      const right = resolveExprIdentities(state, expr.right);
      return { flat: new Set([...left.flat, ...right.flat]), byPath: new Map(), widened: false };
    }

    case 'union': {
      const flat = new Set();
      for (const branch of expr.branches) {
        const r = resolveExprIdentities(state, branch);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: false };
    }

    case 'call': {
      const flat = new Set();
      for (const arg of expr.args ?? []) {
        const r = resolveExprIdentities(state, arg);
        for (const id of r.flat) flat.add(id);
      }
      return { flat, byPath: new Map(), widened: flat.size > 0 };
    }

    case 'assign-expr': {
      // Nested assignment-as-expression (e.g. `if ((x = getUser()).isAdmin)`)
      // is read-only here: resolves what the expression VALUE carries but
      // does NOT write into `x` in `state` — see
      // scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md §4 for why this is a
      // deliberate, documented limitation, not an oversight.
      const r = resolveExprIdentities(state, expr.source);
      return { flat: r.flat, byPath: new Map(), widened: r.flat.size > 0 };
    }

    default:
      return noIdentity();
  }
}
