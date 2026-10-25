// Shared loader for the DAG-02 demand-query tests and benchmark: turns a set of
// JS sources (a fixture directory or an in-memory map) into the perFileIR and
// call graph the taint engine consumes.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildClassHierarchy, annotateRTA } from '../../src/ir/class-hierarchy.js';

export const DEMAND_FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'demand');

export function programFromFiles(files) {
  const perFileIR = {};
  for (const [f, code] of Object.entries(files)) perFileIR[f] = parseJsFile(f, code);
  const callGraph = buildCallGraph(perFileIR, files);
  return { files, perFileIR, callGraph };
}

export function loadFixtureProgram(name) {
  const dir = path.join(DEMAND_FIXTURES, name);
  const files = {};
  for (const f of fs.readdirSync(dir).sort()) if (f.endsWith('.js')) files[f] = fs.readFileSync(path.join(dir, f), 'utf8');
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : null;
  const prog = programFromFiles(files);
  let engineOpts = {};
  if (manifest && manifest.cha) {
    const cha = buildClassHierarchy(prog.perFileIR, prog.callGraph);
    annotateRTA(cha, prog.perFileIR);
    engineOpts = { _cha: cha };
  }
  return { name, manifest, engineOpts, ...prog };
}

export function listFixturePrograms() {
  return fs.readdirSync(DEMAND_FIXTURES).filter((d) => fs.statSync(path.join(DEMAND_FIXTURES, d)).isDirectory()).sort();
}
