import { z } from 'zod';
import { fallbackAnnotation, getCopilotVersion } from './fallback.js';
import type { DeterministicReviewDecision } from './decision.js';
import type { ReviewAnnotation, ReviewCopilotCategory, ReviewCopilotSuggestion, ReviewQuarantineItem } from './types.js';

const CATEGORY_VALUES = [
  'credential_leak',
  'prompt_injection',
  'exfiltration_attempt',
  'scope_escalation',
  'persistence_attempt',
  'documentation_or_example',
  'benign_log',
  'uncertain',
] as const;

const ACTION_VALUES = [
  'approve',
  'reject',
  'keep_quarantined',
  'create_rule',
] as const;

export const REVIEW_COPILOT_CATEGORIES = CATEGORY_VALUES;
export const REVIEW_COPILOT_SUGGESTIONS = ACTION_VALUES;

function boundedString(max: number) {
  return z.string().transform((value) => value.slice(0, max));
}

const evidenceSchema = z.object({
  snippet: boundedString(200),
  reason: boundedString(120),
});

const annotationSchema = z.object({
  itemId: z.union([z.string(), z.number()]).transform((value) => String(value)),
  category: z.enum(CATEGORY_VALUES).optional(),
  summary: boundedString(240),
  evidence: z.array(evidenceSchema).max(3),
  suggestedAction: z.enum(ACTION_VALUES).optional(),
  confidence: z.number().min(0).max(1).optional(),
  similarGroupKey: boundedString(120).nullable().optional(),
  reasoning: boundedString(400),
  copilotVersion: boundedString(160).optional(),
  generatedAt: z.string().optional(),
  synthetic: z.boolean().optional(),
});

const APPROVE_SAFE_CATEGORIES = new Set<ReviewCopilotCategory>([
  'documentation_or_example',
  'benign_log',
]);

const RISKY_APPROVAL_PATTERN = /\b(ignore|override|system prompt|developer message|approve (it|this)|mark (it|this).{0,20}safe|exfil|env vars?|environment variables?|private key|ssh\/id_rsa|token|password|secret|api[_-]?key|bearer)\b/i;

function normaliseSuggestedAction(
  category: ReviewCopilotCategory,
  action: ReviewCopilotSuggestion,
  content: string,
): ReviewCopilotSuggestion {
  if (action !== 'approve') return action;
  if (!APPROVE_SAFE_CATEGORIES.has(category)) return 'keep_quarantined';
  if (RISKY_APPROVAL_PATTERN.test(content)) return 'keep_quarantined';
  return action;
}

export type ReviewAnnotationValidation =
  | { ok: true; annotation: ReviewAnnotation }
  | { ok: false; reason: string; annotation: ReviewAnnotation };

export function extractJsonObject(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('empty_output');
  try {
    return JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start === -1 || end === -1 || end <= start) throw new Error('invalid_json');
    return JSON.parse(trimmed.slice(start, end + 1));
  }
}

export function validateReviewAnnotation(
  value: unknown,
  item: ReviewQuarantineItem,
  modelId: string,
  decision?: DeterministicReviewDecision,
): ReviewAnnotationValidation {
  const fallback = (reason: string): ReviewAnnotationValidation => ({
    ok: false,
    reason,
    annotation: fallbackAnnotation(item, modelId, reason),
  });

  const parsed = annotationSchema.safeParse(value);
  if (!parsed.success) {
    return fallback(`schema_validation_failed: ${parsed.error.issues[0]?.message ?? 'invalid annotation'}`);
  }

  const content = item.content ?? '';
  const evidence = parsed.data.evidence.filter((entry) => (
    entry.snippet.trim().length > 0 && content.includes(entry.snippet)
  ));

  return {
    ok: true,
    annotation: {
      itemId: String(item.id),
      category: decision?.category ?? parsed.data.category ?? 'uncertain',
      summary: parsed.data.summary,
      evidence,
      suggestedAction: decision?.suggestedAction ?? normaliseSuggestedAction(
        parsed.data.category ?? 'uncertain',
        parsed.data.suggestedAction ?? 'keep_quarantined',
        content,
      ),
      confidence: decision?.confidence ?? parsed.data.confidence ?? 0.5,
      similarGroupKey: parsed.data.similarGroupKey ?? null,
      reasoning: parsed.data.reasoning,
      copilotVersion: parsed.data.copilotVersion ?? getCopilotVersion(modelId),
      generatedAt: parsed.data.generatedAt ?? new Date().toISOString(),
      synthetic: false,
    },
  };
}

export function parseReviewAnnotation(
  rawText: string | null | undefined,
  item: ReviewQuarantineItem,
  modelId: string,
  decision?: DeterministicReviewDecision,
): ReviewAnnotationValidation {
  if (!rawText) {
    return {
      ok: false,
      reason: 'model_unavailable',
      annotation: fallbackAnnotation(item, modelId, 'model_unavailable'),
    };
  }
  try {
    return validateReviewAnnotation(extractJsonObject(rawText), item, modelId, decision);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      reason,
      annotation: fallbackAnnotation(item, modelId, reason),
    };
  }
}
