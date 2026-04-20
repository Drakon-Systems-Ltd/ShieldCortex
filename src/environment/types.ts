export type TaintLabel = 'trusted' | 'untrusted' | 'suspicious' | 'hostile';

export interface ProvenanceSignals {
  tls: boolean;
  redirectCount: number;
  redirectChain: string[];
  finalDomain: string;
  suspiciousTld: boolean;
  allowlisted: boolean;
  denylisted: boolean;
  isIpAddress: boolean;
  hasUserInfo: boolean;
  hasPunycode: boolean;
}

export interface ProvenanceResult {
  score: number;
  signals: ProvenanceSignals;
  reasons: string[];
}

export interface HiddenInstructionHit {
  technique:
    | 'display_none'
    | 'visibility_hidden'
    | 'zero_font_size'
    | 'same_colour_text'
    | 'offscreen_position'
    | 'aria_hidden'
    | 'html_comment'
    | 'script_tag'
    | 'bidi_override'
    | 'zero_width_text'
    | 'data_attribute'
    | 'meta_refresh';
  sample: string;
  charCount: number;
}

export interface HiddenAnalysis {
  hits: HiddenInstructionHit[];
  hiddenCharCount: number;
  visibleText: string;
  hiddenText: string;
}

export interface InjectionHit {
  surface: 'visible' | 'hidden';
  pattern: string;
  snippet: string;
}

export interface EnvironmentScanResult {
  url: string;
  finalUrl: string;
  statusCode: number | null;
  contentType: string | null;
  fetchedAt: string;
  fetchDurationMs: number;
  bytesReceived: number;
  error: string | null;

  provenance: ProvenanceResult;
  hidden: HiddenAnalysis;
  injection: {
    visibleHits: InjectionHit[];
    hiddenHits: InjectionHit[];
  };
  taint: {
    label: TaintLabel;
    reason: string;
  };
  risks: string[];
  summary: string;
}
