//
// Data classification model (Data Flow Explorer PRD section 9). Reuses
// scanner/src/dataflow/privacy-taxonomy.js for the PII/PHI/PCI/FIN/
// CREDENTIALS/GEOLOCATION/DEVICE_ID classes and their versioned,
// operator-extensible pattern config — PRD section 3 names this module
// explicitly as reusable, not something to re-implement. This file adds
// only what privacy-taxonomy.js does not already have: the CONFIDENTIAL
// class (PRD 9.1's 8th built-in class — proprietary/business-confidential
// data has no reliable field-NAME pattern, unlike PII/PHI/PCI, so it
// ships with zero default patterns and is populated entirely through the
// same operator-config extension mechanism privacy-taxonomy.js already
// supports) and the AI processing context enum (PRD 9.2), which is
// DELIBERATELY ORTHOGONAL to data class — see the PRD's explicit warning
// against modeling AI as a mutually-exclusive label.

import { DEFAULT_TAXONOMY, classifyFieldAgainst, compileTaxonomy } from '../dataflow/privacy-taxonomy.js';

// PRD section 9.2 — all 15 supported AI processing contexts. "AI" as a
// filter means "matches ANY of these", never a single flag.
export const AI_PROCESSING_CONTEXTS = Object.freeze([
  'ai.system_prompt', 'ai.user_prompt', 'ai.model_input', 'ai.model_output',
  'ai.rag_context', 'ai.embedding', 'ai.vector_store', 'ai.memory',
  'ai.tool_argument', 'ai.tool_result', 'ai.training_data',
  'ai.fine_tuning_data', 'ai.evaluation_data', 'ai.telemetry', 'ai.model_artifact',
]);

// CONFIDENTIAL ships with no default patterns on purpose — "confidential
// business data" has no reliable field-name regex the way "ssn" or
// "diagnosis" does. An operator adds patterns via the SAME
// .agentic-security/privacy-taxonomy.json extension mechanism
// privacy-taxonomy.js already documents (a class name not already in
// DEFAULT_TAXONOMY is accepted as a brand-new organization-defined class).
const _CONFIDENTIAL_EXTRA = Object.freeze({ severity: 'medium', patterns: [] });

export const LINEAGE_DATA_CLASSES = Object.freeze([...Object.keys(DEFAULT_TAXONOMY), 'CONFIDENTIAL']);

const _COMPILED_WITH_CONFIDENTIAL = compileTaxonomy({ ...DEFAULT_TAXONOMY, CONFIDENTIAL: _CONFIDENTIAL_EXTRA });

export function isAiContext(value) {
  return AI_PROCESSING_CONTEXTS.includes(value);
}

/**
 * Classify a data element's canonical/declared name against the
 * (privacy-taxonomy-plus-CONFIDENTIAL) class list. Returns
 * `{classes: string[], aiContexts: []}` — aiContexts is ALWAYS empty from
 * this function: a name alone can never prove a field reaches an AI
 * processing context (PRD 10.5/FR-205 — that requires actual lineage
 * evidence connecting the field to a model input/prompt/embedding/etc.,
 * which is Milestone 1 scope). Callers must not skip that proof step by
 * reading a non-empty aiContexts here; it is shaped this way specifically
 * so there is nothing to accidentally read.
 */
export function classifyDataElementName(name, compiled = _COMPILED_WITH_CONFIDENTIAL) {
  return { classes: classifyFieldAgainst(name, compiled), aiContexts: [] };
}
