//
// Adapter: shared IR (`buildProjectIR`) -> symbol-graph/1.
//
// The IR is REUSED, not copied. All languages the IR lowers (JS/TS, Python, Java, C#, Kotlin, Go, PHP, Ruby, Rust,
// C/C++, and Haskell through the shared call graph) arrive through the one call graph, so this adapter has no
// per-language logic; per-language capability is a matter for the capability matrix, not for branching here.
import { buildProjectIR } from '../../ir/index.js';
import { buildSymbolGraph } from '../graph-schema.js';

export function graphFromSource(fileContents) {
  const { perFile, callGraph } = buildProjectIR(fileContents);
  const graph = buildSymbolGraph({ fileContents, functions: callGraph.functions, edges: callGraph.edges });
  return { graph, perFile, callGraph };
}
