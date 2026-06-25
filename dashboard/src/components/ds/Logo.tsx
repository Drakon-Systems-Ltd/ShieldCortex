/**
 * The canonical ShieldCortex brand mark — the circuit-brain hexagon. Uses the
 * TRIMMED mark (public/shieldcortex-mark.png, transparent margins cropped) so the
 * emblem fills its box; `size` is the rendered height in px and width follows the
 * mark's natural aspect ratio. One source of truth across the dashboard.
 */
export function Logo({ size = 28, className = '' }: { size?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element -- static local brand asset; next/image adds no value here
    <img
      src="/shieldcortex-mark.png"
      alt="ShieldCortex"
      height={size}
      className={className}
      style={{ height: size, width: 'auto' }}
    />
  );
}
