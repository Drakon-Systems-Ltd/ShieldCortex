import type { HiddenAnalysis, HiddenInstructionHit } from './types.js';

const HIDDEN_SAMPLE_CHARS = 120;

function stripTagContent(html: string, tagNames: string[]): string {
  let out = html;
  for (const tag of tagNames) {
    const re = new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?</${tag}>`, 'gi');
    out = out.replace(re, ' ');
  }
  return out;
}

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, '&')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_, n) => {
      const code = parseInt(n, 10);
      return Number.isFinite(code) && code < 0x10ffff ? String.fromCodePoint(code) : '';
    });
}

function innerText(rawHtml: string): string {
  const withoutComments = rawHtml.replace(/<!--[\s\S]*?-->/g, ' ');
  const withoutScripts = stripTagContent(withoutComments, ['script', 'style', 'noscript', 'template']);
  const withoutTags = withoutScripts.replace(/<[^>]+>/g, ' ');
  return decodeHtmlEntities(withoutTags).replace(/\s+/g, ' ').trim();
}

function collectHiddenSpans(html: string): Array<{ technique: HiddenInstructionHit['technique']; text: string }> {
  const results: Array<{ technique: HiddenInstructionHit['technique']; text: string }> = [];

  const patterns: Array<[HiddenInstructionHit['technique'], RegExp]> = [
    ['display_none', /<([a-z][\w-]*)\b[^>]*style=["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi],
    ['visibility_hidden', /<([a-z][\w-]*)\b[^>]*style=["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi],
    ['zero_font_size', /<([a-z][\w-]*)\b[^>]*style=["'][^"']*font-size\s*:\s*0(?:px|em|rem)?[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi],
    ['offscreen_position', /<([a-z][\w-]*)\b[^>]*style=["'][^"']*(?:position\s*:\s*absolute[^"']*(?:left|top)\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{4,})[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi],
    ['aria_hidden', /<([a-z][\w-]*)\b[^>]*aria-hidden=["']true["'][^>]*>([\s\S]*?)<\/\1>/gi],
  ];

  for (const [technique, re] of patterns) {
    let match: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((match = re.exec(html)) !== null) {
      const body = match[2];
      if (!body) continue;
      const text = innerText(body);
      if (text.length > 0) results.push({ technique, text });
    }
  }

  return results;
}

function detectSameColourText(html: string): string[] {
  const hits: string[] = [];
  const re = /<([a-z][\w-]*)\b[^>]*style=["'][^"']*color\s*:\s*(#fff(?:fff)?|white)[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const text = innerText(match[3] || '');
    if (text.length > 0) hits.push(text);
  }
  return hits;
}

function detectComments(html: string): string[] {
  const hits: string[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const text = match[1].trim();
    if (text.length > 40) hits.push(text);
  }
  return hits;
}

function detectScriptTags(html: string): string[] {
  const hits: string[] = [];
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const body = match[1].trim();
    if (body.length > 0) hits.push(body);
  }
  return hits;
}

function detectBidiOverride(html: string): boolean {
  return /[\u202A-\u202E\u2066-\u2069]/.test(html);
}

function detectZeroWidth(html: string): boolean {
  return /[\u200B\u200C\u200D\uFEFF]/.test(html);
}

function detectMetaRefresh(html: string): string | null {
  const match = html.match(/<meta\b[^>]*http-equiv=["']refresh["'][^>]*content=["']([^"']+)["']/i);
  return match ? match[1] : null;
}

function clip(text: string, max = HIDDEN_SAMPLE_CHARS): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function analyseHidden(rawHtml: string): HiddenAnalysis {
  const hits: HiddenInstructionHit[] = [];

  for (const { technique, text } of collectHiddenSpans(rawHtml)) {
    hits.push({ technique, sample: clip(text), charCount: text.length });
  }

  for (const text of detectSameColourText(rawHtml)) {
    hits.push({ technique: 'same_colour_text', sample: clip(text), charCount: text.length });
  }

  for (const text of detectComments(rawHtml)) {
    hits.push({ technique: 'html_comment', sample: clip(text), charCount: text.length });
  }

  for (const text of detectScriptTags(rawHtml)) {
    hits.push({ technique: 'script_tag', sample: clip(text), charCount: text.length });
  }

  if (detectBidiOverride(rawHtml)) {
    hits.push({ technique: 'bidi_override', sample: 'Unicode bidi override characters present', charCount: 0 });
  }

  if (detectZeroWidth(rawHtml)) {
    hits.push({ technique: 'zero_width_text', sample: 'Zero-width characters present in document', charCount: 0 });
  }

  const metaRefresh = detectMetaRefresh(rawHtml);
  if (metaRefresh) {
    hits.push({ technique: 'meta_refresh', sample: clip(metaRefresh), charCount: metaRefresh.length });
  }

  const visible = innerText(rawHtml);
  const hiddenText = hits
    .filter((h) => h.technique !== 'script_tag' && h.technique !== 'html_comment' && h.charCount > 0)
    .map((h) => h.sample)
    .join(' ');

  return {
    hits,
    hiddenCharCount: hits.reduce((acc, h) => acc + h.charCount, 0),
    visibleText: visible,
    hiddenText,
  };
}
