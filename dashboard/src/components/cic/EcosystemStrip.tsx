'use client';

/**
 * The agentic ecosystem feeding the cortex, rendered as a sensor array: each
 * active source (claude-code, openclaw, mcp:*, sub-agents…) is a sensor chip
 * with its throughput. This is the "defends the WHOLE ecosystem" proof, on screen.
 */
export interface EcosystemSource {
  source: string;
  count: number;
}

/** Shorten a raw source id (e.g. "agent:openclaw-plugin:abc") to a sensor label. */
function sensorLabel(source: string): string {
  if (!source) return 'unknown';
  const [type, id] = source.split(':');
  if (type === 'agent' && id) return id.replace(/-plugin.*/, '');
  if (type === 'cli') return id ? `cli:${id}` : 'cli';
  if (type === 'hook') return 'hook';
  if (type === 'api') return id ? `api:${id}` : 'api';
  if (type === 'user') return 'you';
  return type || source;
}

export function EcosystemStrip({ sources = [], max = 4 }: { sources?: EcosystemSource[]; max?: number }) {
  const shown = sources.slice(0, max);
  const extra = sources.length - shown.length;
  return (
    <div className="flex shrink-0 items-center gap-2">
      <span className="shrink-0 text-[var(--cic-text-faint)]">ECOSYSTEM ▸</span>
      {shown.length === 0 ? (
        <span className="text-[var(--cic-text-faint)]">no signals</span>
      ) : (
        shown.map((s) => (
          <span key={s.source} className="flex shrink-0 items-center gap-1" title={`${s.source} · ${s.count} ops`}>
            <span className="cic-bloom text-[var(--cic-cyan)]" aria-hidden>
              ◉
            </span>
            <span className="text-[var(--cic-text-dim)]">{sensorLabel(s.source)}</span>
          </span>
        ))
      )}
      {extra > 0 && <span className="shrink-0 text-[var(--cic-text-faint)]">+{extra}</span>}
    </div>
  );
}
