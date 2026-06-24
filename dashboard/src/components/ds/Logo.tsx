/**
 * The canonical ShieldCortex brand mark — the circuit-brain hexagon
 * (public/shieldcortex-logo.png, transparent). One source of truth so every
 * dashboard surface renders the same logo as the website + npm package.
 */
export function Logo({ size = 24, className = '' }: { size?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element -- static local brand asset; next/image adds no value here
    <img
      src="/shieldcortex-logo.png"
      alt="ShieldCortex"
      width={size}
      height={size}
      className={className}
      style={{ width: size, height: size }}
    />
  );
}
