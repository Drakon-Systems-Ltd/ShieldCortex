import { scanForInjection } from '../defence/iron-dome/injection-scanner.js';
import { fetchWithProvenance } from './fetcher.js';
import { scoreProvenance } from './provenance.js';
import { analyseHidden } from './hidden-detector.js';
import { deriveTaint } from './taint.js';
import type { EnvironmentScanResult, InjectionHit } from './types.js';

function toHits(detections: ReturnType<typeof scanForInjection>['detections'], surface: InjectionHit['surface']): InjectionHit[] {
  return detections.map((d) => ({
    surface,
    pattern: `${d.category}/${d.pattern}`,
    snippet: d.match,
  }));
}

function buildRisks(args: {
  provenance: ReturnType<typeof scoreProvenance>;
  hidden: ReturnType<typeof analyseHidden>;
  visibleHits: InjectionHit[];
  hiddenHits: InjectionHit[];
  statusCode: number | null;
}): string[] {
  const risks: string[] = [];

  if (args.hiddenHits.length > 0) {
    risks.push(`${args.hiddenHits.length} injection pattern${args.hiddenHits.length === 1 ? '' : 's'} found in HIDDEN content — humans will never see this.`);
  }
  if (args.visibleHits.length > 0) {
    risks.push(`${args.visibleHits.length} injection pattern${args.visibleHits.length === 1 ? '' : 's'} found in visible content.`);
  }

  const htmlComments = args.hidden.hits.filter((h) => h.technique === 'html_comment');
  if (htmlComments.length > 0) {
    risks.push(`${htmlComments.length} substantial HTML comment${htmlComments.length === 1 ? '' : 's'} — review for hidden agent instructions.`);
  }

  const layoutHides = args.hidden.hits.filter((h) => ['display_none', 'visibility_hidden', 'zero_font_size', 'offscreen_position', 'same_colour_text'].includes(h.technique));
  if (layoutHides.length > 0) {
    risks.push(`${layoutHides.length} CSS-hidden text region${layoutHides.length === 1 ? '' : 's'} — content visible to an agent parser but not a human reader.`);
  }

  if (args.hidden.hits.some((h) => h.technique === 'bidi_override')) {
    risks.push('Unicode bidi override characters found — possible rendering-vs-parsing deception.');
  }
  if (args.hidden.hits.some((h) => h.technique === 'meta_refresh')) {
    risks.push('Meta refresh redirect in document — agent may be steered to a different page.');
  }
  if (args.hidden.hits.some((h) => h.technique === 'zero_width_text')) {
    risks.push('Zero-width characters in document — possible obfuscation or watermark.');
  }

  if (!args.provenance.signals.tls) risks.push('Fetched over plain HTTP — content integrity not verified.');
  if (args.provenance.signals.denylisted) risks.push(`Final domain is denylisted: ${args.provenance.signals.finalDomain}.`);
  if (args.provenance.signals.suspiciousTld) risks.push(`Final domain uses a suspicious TLD (.${args.provenance.signals.finalDomain.split('.').pop()}).`);
  if (args.provenance.signals.hasPunycode) risks.push('Domain uses Punycode — possible homograph attack against a known brand.');
  if (args.provenance.signals.isIpAddress) risks.push('Request went to a raw IP address rather than a domain name.');

  if (args.statusCode && args.statusCode >= 400) risks.push(`HTTP ${args.statusCode} — response may be an error page rather than the intended content.`);

  return risks;
}

function buildSummary(result: Pick<EnvironmentScanResult, 'taint' | 'provenance' | 'injection' | 'hidden' | 'finalUrl'>): string {
  const lines: string[] = [];
  lines.push(`Taint: ${result.taint.label.toUpperCase()} — ${result.taint.reason}`);
  lines.push(`Provenance score: ${result.provenance.score.toFixed(2)} (${result.provenance.signals.finalDomain})`);
  lines.push(`Visible injection hits: ${result.injection.visibleHits.length}`);
  lines.push(`Hidden injection hits: ${result.injection.hiddenHits.length}`);
  lines.push(`Hidden content techniques: ${result.hidden.hits.length > 0 ? Array.from(new Set(result.hidden.hits.map((h) => h.technique))).join(', ') : 'none'}`);
  return lines.join('\n');
}

export async function scanUrl(url: string): Promise<EnvironmentScanResult> {
  const fetched = await fetchWithProvenance(url);

  const provenance = scoreProvenance({
    originalUrl: url,
    finalUrl: fetched.finalUrl,
    redirectChain: fetched.redirectChain,
  });

  if (fetched.error || !fetched.body) {
    const hidden = { hits: [], hiddenCharCount: 0, visibleText: '', hiddenText: '' };
    const injection = { visibleHits: [] as InjectionHit[], hiddenHits: [] as InjectionHit[] };
    const taint = deriveTaint({ provenance, hidden, visibleHits: [], hiddenHits: [] });
    const risks = buildRisks({ provenance, hidden, visibleHits: [], hiddenHits: [], statusCode: fetched.statusCode });
    if (fetched.error) risks.unshift(`Fetch failed: ${fetched.error}`);
    const partial = { taint, provenance, injection, hidden, finalUrl: fetched.finalUrl };
    return {
      url,
      finalUrl: fetched.finalUrl,
      statusCode: fetched.statusCode,
      contentType: fetched.contentType,
      fetchedAt: new Date().toISOString(),
      fetchDurationMs: fetched.durationMs,
      bytesReceived: fetched.bytesReceived,
      error: fetched.error,
      provenance,
      hidden,
      injection,
      taint,
      risks,
      summary: buildSummary(partial),
    };
  }

  const hidden = analyseHidden(fetched.body);
  const visibleScan = scanForInjection(hidden.visibleText);
  const hiddenScan = scanForInjection(hidden.hiddenText);
  const injection = {
    visibleHits: toHits(visibleScan.detections, 'visible'),
    hiddenHits: toHits(hiddenScan.detections, 'hidden'),
  };

  const taint = deriveTaint({ provenance, hidden, visibleHits: injection.visibleHits, hiddenHits: injection.hiddenHits });
  const risks = buildRisks({ provenance, hidden, visibleHits: injection.visibleHits, hiddenHits: injection.hiddenHits, statusCode: fetched.statusCode });
  const partial = { taint, provenance, injection, hidden, finalUrl: fetched.finalUrl };

  return {
    url,
    finalUrl: fetched.finalUrl,
    statusCode: fetched.statusCode,
    contentType: fetched.contentType,
    fetchedAt: new Date().toISOString(),
    fetchDurationMs: fetched.durationMs,
    bytesReceived: fetched.bytesReceived,
    error: null,
    provenance,
    hidden,
    injection,
    taint,
    risks,
    summary: buildSummary(partial),
  };
}
