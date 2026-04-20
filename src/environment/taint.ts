import type { HiddenAnalysis, InjectionHit, ProvenanceResult, TaintLabel } from './types.js';

export function deriveTaint(args: {
  provenance: ProvenanceResult;
  hidden: HiddenAnalysis;
  visibleHits: InjectionHit[];
  hiddenHits: InjectionHit[];
}): { label: TaintLabel; reason: string } {
  const { provenance, hidden, visibleHits, hiddenHits } = args;

  if (provenance.signals.denylisted) {
    return { label: 'hostile', reason: `Denylisted domain (${provenance.signals.finalDomain})` };
  }

  if (hiddenHits.length > 0) {
    return {
      label: 'hostile',
      reason: `Injection pattern found inside hidden content (${hiddenHits.length} hit${hiddenHits.length === 1 ? '' : 's'})`,
    };
  }

  if (hidden.hits.some((h) => h.technique === 'bidi_override')) {
    return { label: 'suspicious', reason: 'Unicode bidi override characters detected (render vs parse mismatch risk)' };
  }

  const highRiskHidden = hidden.hits.filter((h) =>
    h.technique === 'display_none' ||
    h.technique === 'zero_font_size' ||
    h.technique === 'same_colour_text' ||
    h.technique === 'offscreen_position' ||
    h.technique === 'visibility_hidden',
  );
  const highRiskHiddenChars = highRiskHidden.reduce((acc, h) => acc + h.charCount, 0);

  if (highRiskHidden.length >= 3 || highRiskHiddenChars >= 150) {
    return {
      label: 'suspicious',
      reason: `Hidden content via ${highRiskHidden[0]?.technique ?? 'layout tricks'} (${highRiskHidden.length} region${highRiskHidden.length === 1 ? '' : 's'}, ${highRiskHiddenChars} chars)`,
    };
  }

  if (visibleHits.length > 0) {
    return {
      label: 'suspicious',
      reason: `Injection pattern in visible content (${visibleHits.length} hit${visibleHits.length === 1 ? '' : 's'})`,
    };
  }

  if (provenance.signals.allowlisted && provenance.score >= 0.7) {
    return { label: 'trusted', reason: `Allowlisted domain (${provenance.signals.finalDomain})` };
  }

  if (provenance.score >= 0.6) {
    return { label: 'untrusted', reason: `No hostile signals, provenance score ${provenance.score.toFixed(2)}` };
  }

  return {
    label: 'suspicious',
    reason: `Low provenance score (${provenance.score.toFixed(2)}): ${provenance.reasons.slice(0, 2).join('; ')}`,
  };
}
