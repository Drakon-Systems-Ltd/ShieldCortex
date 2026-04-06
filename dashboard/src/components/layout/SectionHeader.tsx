interface SectionHeaderProps {
  eyebrow?: string;
  title: string;
  description: string;
}

export function SectionHeader({ eyebrow, title, description }: SectionHeaderProps) {
  return (
    <div className="mb-8">
      {eyebrow ? (
        <div className="text-[11px] uppercase tracking-[0.22em] text-[var(--sc-cyan)]">{eyebrow}</div>
      ) : null}
      <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--sc-text-primary)]">{title}</h1>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-[var(--sc-text-secondary)]">{description}</p>
    </div>
  );
}
