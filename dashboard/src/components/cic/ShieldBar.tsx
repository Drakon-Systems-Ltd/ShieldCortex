'use client';

/**
 * The 6-layer defence shield, as a tactical integrity bar. Each segment is one
 * pipeline layer; the bar reads coral when blocks are landing, cyan when the
 * shield is quiet but armed.
 */
const LAYERS = ['input', 'pattern', 'semantic', 'structural', 'behaviour', 'credential'];

export function ShieldBar({ blocked = 0 }: { blocked?: number }) {
  const hot = blocked > 0;
  const colour = hot ? 'var(--cic-coral)' : 'var(--cic-cyan)';
  return (
    <div className="flex shrink-0 items-center gap-2" title={`Shield: 6 layers armed · ${blocked} blocked`}>
      <span className="text-[var(--cic-text-faint)]">SHIELD</span>
      <span className="flex gap-0.5">
        {LAYERS.map((l) => (
          <span
            key={l}
            className={hot ? 'cic-bloom' : ''}
            style={{ color: colour }}
            aria-hidden
          >
            ▣
          </span>
        ))}
      </span>
    </div>
  );
}
