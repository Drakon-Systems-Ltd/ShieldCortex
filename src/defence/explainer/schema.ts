import { z } from 'zod';
import { extractJsonObject } from '../judge/schema.js';
import type { LocalAiExplanation, LocalAiExplainSubject } from './types.js';

function boundedString(max: number) {
  return z.string().transform((value) => value.slice(0, max));
}

const evidenceSchema = z.object({
  snippet: boundedString(220),
  reason: boundedString(180),
});

const explanationSchema = z.object({
  summary: boundedString(240),
  whyItMatters: boundedString(500),
  evidence: z.array(evidenceSchema).max(4).default([]),
  nextSteps: z.array(boundedString(180)).max(5).default([]),
  riskSignals: z.array(boundedString(80)).max(8).default([]),
  confidence: z.number().min(0).max(1).default(0.5),
});

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(previous|all|the above)\s+instructions?/i,
  /override\s+(system|developer|safety)\s+instructions?/i,
  /reveal\s+(the\s+)?(system prompt|developer message|api keys?|secrets?|tokens?)/i,
  /exfiltrat(?:e|ion)/i,
  /act\s+as\s+(?:a\s+)?system/i,
];

const CREDENTIAL_PATTERNS = [
  /\b[A-Z0-9_]*(API|TOKEN|SECRET|KEY)[A-Z0-9_]*\b/,
  /\bgh\s+secret\s+set\b/i,
  /\bfly\s+tokens?\s+create\b/i,
  /api[_\s-]?keys?/i,
  /bearer\s+[a-z0-9._-]{12,}/i,
  /password\s*[:=]/i,
  /secret\s*[:=]/i,
  /token\s*[:=]/i,
  /BEGIN\s+[A-Z ]*PRIVATE KEY/i,
];

const UNSAFE_MODEL_OUTPUT_PATTERN =
  /\b(prompt_user_for_api_key|provide\s+(an?\s+)?api\s+key|enter\s+(an?\s+)?api\s+key|share\s+(the\s+)?(secret|token|password|api\s+key)|reveal\s+(the\s+)?(secret|token|password|api\s+key)|mark\s+(it|this)\s+safe|approve\s+(it|this))\b/i;

function subjectSignals(subject: LocalAiExplainSubject): string[] {
  const signals = subject.signals?.map((signal) => signal.trim()).filter(Boolean) ?? [];
  if (PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(subject.content))) {
    signals.push('prompt_injection');
  }
  if (CREDENTIAL_PATTERNS.some((pattern) => pattern.test(subject.content))) {
    signals.push('credential_reference');
  }
  return [...new Set(signals)].slice(0, 8);
}

function hasSignal(subject: LocalAiExplainSubject, values: string[]): boolean {
  const haystack = [
    subject.kind,
    subject.title,
    ...(subject.signals ?? []),
  ].join(' ').toLowerCase();
  return values.some((value) => haystack.includes(value));
}

function firstSnippet(content: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if (!match || match.index === undefined) continue;
    const start = Math.max(0, match.index - 45);
    const end = Math.min(content.length, match.index + match[0].length + 90);
    return content.slice(start, end).trim();
  }
  return null;
}

function evidenceFromContent(subject: LocalAiExplainSubject): LocalAiExplanation['evidence'] {
  const content = subject.content ?? '';
  const evidence: LocalAiExplanation['evidence'] = [];

  const injectionSnippet = firstSnippet(content, PROMPT_INJECTION_PATTERNS);
  if (injectionSnippet) {
    evidence.push({ snippet: injectionSnippet, reason: 'Prompt-injection wording appears in the source content.' });
  }

  const credentialSnippet = firstSnippet(content, CREDENTIAL_PATTERNS);
  if (credentialSnippet && !evidence.some((entry) => entry.snippet === credentialSnippet)) {
    evidence.push({ snippet: credentialSnippet, reason: 'Credential or secret handling language appears in the source content.' });
  }

  const evidenceLine = content.split('\n').find((line) => line.trim().toLowerCase().startsWith('evidence:'));
  if (evidenceLine && !evidence.some((entry) => entry.snippet === evidenceLine.trim())) {
    const reason = subject.kind === 'xray_finding'
      ? 'X-Ray recorded this as the finding evidence.'
      : subject.kind === 'memory_file'
        ? 'Memory file scan recorded this evidence.'
        : 'ShieldCortex recorded this as evidence.';
    evidence.push({ snippet: evidenceLine.trim(), reason });
  }

  return evidence.slice(0, 4);
}

function fallbackSummary(subject: LocalAiExplainSubject): string {
  if (hasSignal(subject, ['credential', 'secret', 'token', 'password']) || CREDENTIAL_PATTERNS.some((pattern) => pattern.test(subject.content))) {
    return 'Potential credential or secret exposure needs manual review.';
  }
  if (hasSignal(subject, ['prompt_injection', 'injection', 'jailbreak']) || PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(subject.content))) {
    return 'Potential prompt-injection behaviour needs manual review.';
  }
  if (subject.kind === 'xray_finding') {
    return `X-Ray finding needs review: ${subject.title.slice(0, 160)}`;
  }
  if (subject.kind === 'memory_file') {
    return `Persistent memory file needs review: ${subject.title.slice(0, 150)}`;
  }
  return `${subject.kind.replace(/_/g, ' ')} needs manual review.`;
}

function fallbackSteps(subject: LocalAiExplainSubject): string[] {
  if (subject.kind === 'xray_finding') {
    return [
      'Inspect the file or package source referenced by the X-Ray finding.',
      'Use the deterministic X-Ray severity and category before taking action.',
      'Quarantine only if the source or behaviour is unexpected.',
    ];
  }

  if (subject.kind === 'memory') {
    return [
      'Review the memory source and deterministic scan result.',
      'Check whether the content is expected for this project.',
      'Quarantine or delete only after confirming the source is unsafe.',
    ];
  }

  if (subject.kind === 'memory_file') {
    return [
      'Open the memory file path shown in the scan result.',
      'Use the deterministic ShieldCortex risk, indicators, and evidence as the decision source.',
      'Edit or remove risky persistent instructions only after confirming they are unexpected.',
    ];
  }

  return [
    'Review the deterministic scan result and source evidence.',
    'Check whether the content is expected for this project.',
  ];
}

function fallbackText(subject: LocalAiExplainSubject): Pick<LocalAiExplanation, 'summary' | 'whyItMatters' | 'evidence' | 'nextSteps' | 'riskSignals' | 'confidence'> {
  const signals = subjectSignals(subject);
  const signalText = signals.length ? signals.slice(0, 3).join(', ') : 'No specific local model signals were available';
  return {
    summary: fallbackSummary(subject),
    whyItMatters: `${signalText}. Local AI explanation was unavailable, so rely on ShieldCortex deterministic scan output and inspect the source content before taking action.`,
    evidence: evidenceFromContent(subject),
    nextSteps: fallbackSteps(subject),
    riskSignals: signals.slice(0, 8),
    confidence: 0,
  };
}

function operatorReason(reason: string): string {
  if (reason === 'model_output_rejected') return 'model output was rejected by safety checks';
  if (reason === 'model_unavailable') return 'model was unavailable';
  if (reason.includes('JSON') || reason.includes('invalid_json') || reason.includes('schema_validation')) {
    return 'model output was not parseable';
  }
  return reason.slice(0, 160);
}

export function fallbackLocalAiExplanation(
  subject: LocalAiExplainSubject,
  modelId: string,
  reason: string,
): LocalAiExplanation {
  const fallback = fallbackText(subject);
  return {
    kind: subject.kind,
    ...fallback,
    whyItMatters: `${fallback.whyItMatters} (${operatorReason(reason)})`,
    modelId,
    generatedAt: new Date().toISOString(),
    synthetic: true,
  };
}

export function parseLocalAiExplanation(
  rawText: string | null | undefined,
  subject: LocalAiExplainSubject,
  modelId: string,
): LocalAiExplanation {
  if (!rawText) {
    return fallbackLocalAiExplanation(subject, modelId, 'model_unavailable');
  }

  try {
    const parsed = explanationSchema.parse(extractJsonObject(rawText));
    const content = subject.content ?? '';
    const baseline = fallbackText(subject);
    const modelText = [
      parsed.summary,
      parsed.whyItMatters,
      ...parsed.nextSteps,
      ...parsed.riskSignals,
    ].join('\n');

    if (UNSAFE_MODEL_OUTPUT_PATTERN.test(modelText)) {
      return fallbackLocalAiExplanation(subject, modelId, 'model_output_rejected');
    }

    const evidence = parsed.evidence.filter((entry) => (
      entry.snippet.trim().length > 0 && content.includes(entry.snippet)
    ));
    const nextSteps = parsed.nextSteps
      .filter((step) => step.includes(' ') && !step.includes('_'))
      .slice(0, 5);
    const riskSignals = parsed.riskSignals.length > 0
      ? parsed.riskSignals
      : subjectSignals(subject);

    return {
      kind: subject.kind,
      summary: parsed.summary,
      whyItMatters: parsed.whyItMatters,
      evidence: evidence.length > 0 ? evidence : baseline.evidence,
      nextSteps: nextSteps.length >= 2 ? nextSteps : baseline.nextSteps,
      riskSignals: riskSignals.length > 0 ? riskSignals : baseline.riskSignals,
      confidence: parsed.confidence,
      modelId,
      generatedAt: new Date().toISOString(),
      synthetic: false,
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return fallbackLocalAiExplanation(subject, modelId, reason);
  }
}
