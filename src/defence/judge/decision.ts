import { scanForCredentials } from '../credential-leak/index.js';
import { detectInstructions } from '../firewall/instruction-detector.js';
import { detectPrivilegeEscalation } from '../firewall/privilege-detector.js';
import { detectSkillThreats } from '../skill-scanner/patterns.js';
import type {
  ReviewAnnotation,
  ReviewCopilotCategory,
  ReviewCopilotSuggestion,
  ReviewQuarantineItem,
} from './types.js';

export interface DeterministicReviewDecision {
  category: ReviewCopilotCategory;
  suggestedAction: ReviewCopilotSuggestion;
  confidence: number;
  reasoning: string;
  signals: string[];
}

function parseThreatIndicators(value: ReviewQuarantineItem['threatIndicators']): string[] {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String).map((entry) => entry.toLowerCase());
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed.map(String).map((entry) => entry.toLowerCase());
    }
  } catch {
    // Fall through to comma/string parsing.
  }
  return String(value)
    .split(/[,\s]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function includesAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

function isDocumentationLike(text: string): boolean {
  return includesAny(text, [
    /\b(documentation|docs?|readme|blog draft|release note|training note|security training)\b/i,
    /\b(test fixture|unit test|documentation example|docs example|quoted example|benign examples?|placeholder|fake key|not real|expected to be blocked)\b/i,
  ]);
}

function isExplicitlyBenign(text: string): boolean {
  return includesAny(text, [
    /\b(meeting note|project note|support note|design note|operational note|architecture note|reminder|preference)\b/i,
    /\b(no secrets present|metadata only|local-only|advisory)\b/i,
  ]);
}

function deterministicSummary(decision: DeterministicReviewDecision): string {
  switch (decision.category) {
    case 'credential_leak':
      return 'ShieldCortex deterministic scanners found credential material.';
    case 'exfiltration_attempt':
      return 'ShieldCortex deterministic scanners found an exfiltration pattern.';
    case 'scope_escalation':
      return 'ShieldCortex deterministic scanners found a scope-escalation pattern.';
    case 'persistence_attempt':
      return 'ShieldCortex deterministic scanners found a persistence attempt.';
    case 'prompt_injection':
      return 'ShieldCortex deterministic scanners found prompt-injection behaviour.';
    case 'documentation_or_example':
      return 'ShieldCortex classified this as documentation or a test example.';
    case 'benign_log':
      return 'ShieldCortex classified this as a benign operational note.';
    case 'uncertain':
      return 'ShieldCortex could not classify this item confidently.';
  }
}

function rejectOrKeep(item: ReviewQuarantineItem): ReviewCopilotSuggestion {
  return item.firewallResult === 'BLOCK' ? 'reject' : 'keep_quarantined';
}

function decision(
  category: ReviewCopilotCategory,
  suggestedAction: ReviewCopilotSuggestion,
  confidence: number,
  reasoning: string,
  signals: string[],
): DeterministicReviewDecision {
  return {
    category,
    suggestedAction,
    confidence,
    reasoning,
    signals: [...new Set(signals)].slice(0, 12),
  };
}

export function decideReviewAnnotation(item: ReviewQuarantineItem): DeterministicReviewDecision {
  const content = item.content ?? '';
  const title = item.title ?? '';
  const reason = item.reason ?? '';
  const combined = `${title}\n${reason}\n${content}`;
  const indicators = parseThreatIndicators(item.threatIndicators);
  const credentialScan = scanForCredentials(content);
  const skillThreats = detectSkillThreats(content);
  const instructions = detectInstructions(content);
  const privilege = detectPrivilegeEscalation(content);
  const signals = [
    ...indicators.map((indicator) => `indicator:${indicator}`),
    ...skillThreats.threats.map((threat) => `skill:${threat}`),
    ...privilege.indicators.map((indicator) => `privilege:${indicator}`),
    ...credentialScan.findings.map((finding) => `credential:${finding.provider ?? finding.type}:${finding.severity}`),
    ...(instructions.detected ? ['instruction_injection'] : []),
    ...(item.firewallResult ? [`firewall:${item.firewallResult.toLowerCase()}`] : []),
  ];

  const docsLike = isDocumentationLike(combined);
  const benignLike = isExplicitlyBenign(combined);

  if (benignLike && !credentialScan.findings.some((finding) => finding.action === 'blocked')) {
    return decision(
      'benign_log',
      'approve',
      0.78,
      'No deterministic threat signal was found and the content looks operational/benign.',
      signals,
    );
  }

  if (docsLike && !credentialScan.findings.some((finding) => finding.action === 'blocked')) {
    return decision(
      'documentation_or_example',
      'approve',
      0.82,
      'Documentation/test-example language was detected and no live blocked credential pattern was found.',
      [...signals, 'documentation_like'],
    );
  }

  if (credentialScan.leaked || indicators.includes('credential_leak') || indicators.includes('restricted_content')) {
    return decision(
      'credential_leak',
      rejectOrKeep(item),
      credentialScan.findings.some((finding) => finding.action === 'blocked') ? 0.96 : 0.88,
      'Credential leak detection is deterministic and overrides model classification.',
      signals,
    );
  }

  if (
    skillThreats.threats.includes('data_exfiltration') ||
    privilege.indicators.includes('network_exfiltration') ||
    indicators.includes('data_exfiltration') ||
    includesAny(content, [
      /\b(exfiltrate|send|upload|post|curl|forward|include)\b[\s\S]{0,140}\b(https?:|webhook|pastebin|env vars?|environment variables?|\.env|private key|credentials?|api key|cookies?|transcripts?)\b/i,
      /\b(cookies?|api key|credentials?|secrets?)\b[\s\S]{0,140}\b(memory|retrieve|transcripts?|webhook|pastebin|external|attacker)\b/i,
    ])
  ) {
    return decision(
      'exfiltration_attempt',
      rejectOrKeep(item),
      0.94,
      'Deterministic exfiltration patterns were found in the quarantined content.',
      signals,
    );
  }

  if (
    skillThreats.threats.includes('scope_escalation') ||
    indicators.includes('scope_escalation') ||
    indicators.includes('privilege_escalation') ||
    privilege.indicators.includes('system_access') ||
    privilege.indicators.includes('destructive_filesystem') ||
    includesAny(content, [
      /\b(add yourself|add (me|this agent))\b[\s\S]{0,80}\b(admin|administrator|team)\b/i,
      /\bbypass\b[\s\S]{0,80}\b(confirmation|approval|gate|permission)\b/i,
      /\balready approved\b[\s\S]{0,80}\b(future|destructive|commands?)\b/i,
    ])
  ) {
    return decision(
      'scope_escalation',
      rejectOrKeep(item),
      0.9,
      'Deterministic privilege/scope escalation signals were found.',
      signals,
    );
  }

  if (
    skillThreats.threats.includes('persistence') ||
    indicators.includes('persistence') ||
    includesAny(content, [
      /\b(remember|store|create a memory|save)\b[\s\S]{0,80}\b(forever|future|later|every later|hidden rule)\b/i,
      /\b(hidden rule|never show|trust messages? from|attacker\.example)\b/i,
    ])
  ) {
    return decision(
      'persistence_attempt',
      rejectOrKeep(item),
      0.9,
      'Deterministic persistence patterns were found.',
      signals,
    );
  }

  if (
    instructions.detected ||
    skillThreats.threats.includes('agent_manipulation') ||
    skillThreats.threats.includes('stealth_instruction') ||
    indicators.includes('instruction_injection') ||
    includesAny(content, [
      /\b(forget|ignore|override)\b[\s\S]{0,80}\b(policy|instructions?|rules?|safety|security)\b/i,
      /\b(mark|treat)\b[\s\S]{0,40}\b(memory|item|this)\b[\s\S]{0,40}\b(safe|approved?)\b/i,
      /\bapprove\b[\s\S]{0,60}\b(automatically|only|always|this quarantine item)\b/i,
      /\bprefer\b[\s\S]{0,60}\battacker instructions?\b/i,
      /\b(secretly|hidden instruction)\b[\s\S]{0,80}\b(print|reveal|answer only|developer message|approve)\b/i,
      /\bbypass\b[\s\S]{0,80}\b(iron dome|shieldcortex|security|safety)\b/i,
    ])
  ) {
    return decision(
      'prompt_injection',
      rejectOrKeep(item),
      Math.max(0.84, instructions.confidence ?? 0),
      'Deterministic prompt-injection or agent-manipulation patterns were found.',
      signals,
    );
  }

  if (skillThreats.detected || indicators.includes('custom_rule') || indicators.includes('custom_pattern')) {
    return decision(
      'prompt_injection',
      'create_rule',
      Math.max(0.78, skillThreats.confidence),
      'A repeatable deterministic pattern was detected and may warrant a rule.',
      signals,
    );
  }

  if (item.firewallResult === 'ALLOW') {
    return decision(
      'benign_log',
      'approve',
      0.78,
      'No deterministic threat signal was found and the content looks operational/benign.',
      signals,
    );
  }

  return decision(
    'uncertain',
    'keep_quarantined',
    0.5,
    'No deterministic signal was strong enough to classify this item.',
    signals,
  );
}

export function deterministicAnnotation(
  item: ReviewQuarantineItem,
  copilotVersion: string,
  decisionResult: DeterministicReviewDecision,
  reason: string,
): ReviewAnnotation {
  return {
    itemId: String(item.id),
    category: decisionResult.category,
    summary: deterministicSummary(decisionResult),
    evidence: [],
    suggestedAction: decisionResult.suggestedAction,
    confidence: decisionResult.confidence,
    similarGroupKey: null,
    reasoning: `${decisionResult.reasoning} Local model summary unavailable: ${reason}`.slice(0, 400),
    copilotVersion,
    generatedAt: new Date().toISOString(),
    synthetic: false,
  };
}
