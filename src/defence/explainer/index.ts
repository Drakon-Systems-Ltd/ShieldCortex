import { getReviewCopilotConfig } from '../../cloud/config.js';
import { runReviewCopilotPrompt } from '../judge/runner.js';
import { buildLocalAiExplainPrompt } from './prompt.js';
import { fallbackLocalAiExplanation, parseLocalAiExplanation } from './schema.js';
import type { LocalAiExplanation, LocalAiExplainSubject } from './types.js';

export type {
  LocalAiEvidence,
  LocalAiExplanation,
  LocalAiExplainSubject,
  LocalAiExplainSubjectKind,
} from './types.js';

export { buildLocalAiExplainPrompt } from './prompt.js';
export { fallbackLocalAiExplanation, parseLocalAiExplanation } from './schema.js';

function normaliseSubject(subject: LocalAiExplainSubject): LocalAiExplainSubject {
  return {
    ...subject,
    title: subject.title.trim().slice(0, 240),
    content: subject.content.trim().slice(0, 20_000),
    project: subject.project?.trim() || null,
    source: subject.source?.trim() || null,
    signals: subject.signals?.map((signal) => signal.trim()).filter(Boolean).slice(0, 20) ?? [],
  };
}

export async function explainLocalAiSubject(subject: LocalAiExplainSubject): Promise<LocalAiExplanation> {
  const config = getReviewCopilotConfig();
  const normalised = normaliseSubject(subject);

  if (!config.enabled) {
    return fallbackLocalAiExplanation(normalised, config.modelId, 'Local AI Explainer disabled.');
  }

  if (!normalised.title || !normalised.content) {
    return fallbackLocalAiExplanation(normalised, config.modelId, 'Missing title or content.');
  }

  const rawText = await runReviewCopilotPrompt(buildLocalAiExplainPrompt(normalised));
  return parseLocalAiExplanation(rawText, normalised, config.modelId);
}
