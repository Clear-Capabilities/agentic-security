#!/usr/bin/env node
// PRD F5.1 — prompt injection, scored per technique against a published corpus.
//
// ── What is under test, precisely ────────────────────────────────────────────
//
// `scanClaudeMdPromptInjection` is this engine's PAYLOAD detector: given the
// text of a file that will be loaded into an agent's context — CLAUDE.md,
// AGENTS.md, a skill, a rule file — does it carry an instruction aimed at the
// agent rather than at the human reader?
//
// That is the indirect-injection threat this product is actually built for, and
// it is the right thing to score against an injection corpus. The corpus rows
// are chat-style prompts, so each is written into an instruction file and the
// question becomes: if this text arrived inside a document your agent reads,
// would we tell you?
//
// The other LLM modules (`llm.js`, `rag-poisoning.js`, `llm-stored-prompt.js`)
// detect CODE SHAPES — user input reaching a prompt, an unattributed vector
// store write — and take source code as input, not payload text. Scoring them
// against a payload corpus would measure nothing, so they are out of scope
// here and remain unmeasured. Stating that is the point: this bench closes part
// of Feature 5, not all of it.
//
// ── Per technique, never as one aggregate ────────────────────────────────────
//
// Direct override, role-play, exfiltration and encoding-obfuscation have
// genuinely different detection profiles, and an aggregate hides which one is
// weak. The buckets are assigned HERE, from the corpus text, by rules that know
// nothing about the engine's patterns — so a technique the engine cannot see is
// still counted in its own denominator rather than disappearing.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanClaudeMdPromptInjection } from '../../scanner/src/sast/claude-md-prompt-injection.js';
import { CORPUS } from './fetch.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULT = path.join(HERE, 'RESULT.json');

// Technique taxonomy. Bilingual because the corpus is: it is German and
// English, and a detector built only around English phrasing will show up here
// as a per-language gap rather than as a mysterious aggregate shortfall.
const TECHNIQUES = [
  {
    id: 'encoding-obfuscated',
    why: 'the payload is hidden in an encoding or non-printing characters rather than stated in prose',
    re: /\b(base64|rot13|b64decode|atob|hex[- ]?encoded|urlencode|percent[- ]?encoded)\b|[​-‏‪-‮⁠-⁤]|(?:[A-Za-z0-9+/]{40,}={0,2})/i,
  },
  {
    id: 'override',
    why: 'instructs the model to discard its prior instructions',
    re: /\b(ignore|forget|disregard|verg(?:iss|essen)|ignorier)\w*\b[^.]{0,40}\b(previous|prior|above|all|earlier|alle|vorher\w*|obig\w*)\b|\bstop\b[\s\S]{0,20}\b(urgent|dringend)\b|\bnew (task|instruction)\b|\bneue[rs]? (Aufgabe|Anweisung)\b/i,
  },
  {
    id: 'exfiltration',
    why: 'asks the model to reveal its own instructions or context',
    re: /\b(show|reveal|print|repeat|output|tell me|zeig|verrate|nenne)\b[^.]{0,60}\b(prompt|instruction|system message|rule|anweisung|regeln|systemprompt)\w*\b|\bwhat (are|were) your (instructions|rules)\b/i,
  },
  {
    id: 'role-play',
    why: 'reframes the model as a different actor so its constraints read as someone else\'s',
    re: /\b(you are now|act as|pretend to be|from now on you|imagine you are|du bist (jetzt|nun)|verhalte dich|spiele die rolle|tu so als)\b|\bDAN\b|\bjailbreak\b/i,
  },
  {
    id: 'indirect-context',
    why: 'the payload is framed as retrieved content — a document, page or message the agent is reading',
    re: /\b(the following (document|text|email|page|message|article)|as (stated|written) (in|below)|folgende[rsn]? (Dokument|Text|E-?Mail|Nachricht))\b/i,
  },
];

function classify(text) {
  const hits = TECHNIQUES.filter((t) => t.re.test(text)).map((t) => t.id);
  // `other` is a real bucket, not a rounding error: an injection this bench
  // cannot name is still an injection, and hiding it inside a matched bucket
  // would make the taxonomy look more complete than it is.
  return hits.length ? hits : ['other'];
}

// Rough but adequate: the corpus is German and English only, and the question
// is whether a detector built around English phrasing has a blind spot.
function language(text) {
  const de = /\b(und|nicht|eine|ist|das|die|der|ich|für|mit|sie|wie|auf|von|dass|bitte|kann|werden)\b/gi;
  const en = /\b(and|not|the|is|that|this|you|for|with|they|how|from|please|can|will|your)\b/gi;
  const d = (text.match(de) || []).length, e = (text.match(en) || []).length;
  if (d === 0 && e === 0) return 'unknown';
  return d > e ? 'de' : 'en';
}

// The corpus rows are chat prompts. Each is presented the way the threat
// actually arrives: as the content of an instruction file the agent loads.
function detect(text) {
  return scanClaudeMdPromptInjection('AGENTS.md', text) || [];
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

function score(rows) {
  const out = {
    injections: { n: 0, d: 0 },
    legitimate: { correctSilence: 0, d: 0, falsePositives: [] },
    byTechnique: {}, byLanguage: {},
  };
  for (const row of rows) {
    const text = String(row.text || '');
    const flagged = detect(text).length > 0;
    const lang = language(text);
    (out.byLanguage[lang] ||= { injections: { n: 0, d: 0 }, falsePositives: 0, legitimate: 0 });

    if (row.label === 1) {
      out.injections.d++;
      if (flagged) out.injections.n++;
      out.byLanguage[lang].injections.d++;
      if (flagged) out.byLanguage[lang].injections.n++;
      for (const tech of classify(text)) {
        const b = (out.byTechnique[tech] ||= { n: 0, d: 0 });
        b.d++;
        if (flagged) b.n++;
      }
    } else {
      out.legitimate.d++;
      out.byLanguage[lang].legitimate++;
      if (flagged) {
        out.byLanguage[lang].falsePositives++;
        out.legitimate.falsePositives.push(text.slice(0, 140));
      } else {
        out.legitimate.correctSilence++;
      }
    }
  }
  out.recall = { ...out.injections, pct: pct(out.injections.n, out.injections.d) };
  out.correctSilence = {
    n: out.legitimate.correctSilence, d: out.legitimate.d,
    pct: pct(out.legitimate.correctSilence, out.legitimate.d),
  };
  const tp = out.injections.n, fp = out.legitimate.d - out.legitimate.correctSilence;
  out.precision = { n: tp, d: tp + fp, pct: pct(tp, tp + fp) };
  for (const b of Object.values(out.byTechnique)) b.pct = pct(b.n, b.d);
  for (const b of Object.values(out.byLanguage)) b.injections.pct = pct(b.injections.n, b.injections.d);
  return out;
}

function main() {
  if (!fs.existsSync(CORPUS)) {
    process.stderr.write('corpus missing — run `node fetch.mjs` first.\n');
    process.exit(1);
  }
  const corpus = JSON.parse(fs.readFileSync(CORPUS, 'utf8'));
  const development = score(corpus.development);
  const heldOut = score(corpus.heldOut);
  const all = score([...corpus.development, ...corpus.heldOut]);

  const result = {
    prd: 'F5.1',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    corpus: { dataset: corpus.dataset, license: corpus.license, fetchedAt: corpus.fetchedAt },
    scoredSurface: 'scanClaudeMdPromptInjection — the payload detector for instruction files. The code-shape LLM modules take source as input and are NOT scored here.',
    taxonomyOwner: 'this bench, from the corpus text — never from the engine\'s patterns',
    all, development, heldOut,
  };
  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (process.argv.includes('--json')) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }

  const line = (label, s) => process.stdout.write(
    `${label.padEnd(22)} recall ${String(s.recall.n).padStart(3)}/${String(s.recall.d).padStart(3)} = ${String(s.recall.pct).padStart(6)}%   ` +
    `precision ${String(s.precision.n).padStart(3)}/${String(s.precision.d).padStart(3)} = ${String(s.precision.pct).padStart(6)}%   ` +
    `correct-silence ${String(s.correctSilence.n).padStart(3)}/${String(s.correctSilence.d).padStart(3)} = ${String(s.correctSilence.pct).padStart(6)}%\n`);

  process.stdout.write(`\nbench/prompt-injection — engine ${result.engineVersion}, corpus ${corpus.dataset} (${corpus.license})\n\n`);
  line('ALL', all);
  line('development', development);
  line('held-out', heldOut);

  process.stdout.write('\nper technique (all rows):\n');
  for (const [id, b] of Object.entries(all.byTechnique).sort((a, c) => c[1].d - a[1].d)) {
    process.stdout.write(`  ${id.padEnd(22)} ${String(b.n).padStart(3)}/${String(b.d).padStart(3)} = ${String(b.pct).padStart(6)}%\n`);
  }
  process.stdout.write('\nper language (all rows):\n');
  for (const [id, b] of Object.entries(all.byLanguage)) {
    process.stdout.write(`  ${id.padEnd(22)} injections ${String(b.injections.n).padStart(3)}/${String(b.injections.d).padStart(3)} = ${String(b.injections.pct).padStart(6)}%   false positives ${b.falsePositives}/${b.legitimate}\n`);
  }
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main();
