/**
 * #441 renderer half — the precondition must reach the terminal, above the
 * command, on both the plain and the collapsed path.
 *
 * The check-side fix (plane-remedy-441.test.ts) is worthless if the renderer
 * drops `fixWhen` the same way it dropped the prose clause it replaces.
 */
import { describe, expect, it } from '@jest/globals';
import { formatDoctorReport, type DoctorReportItem } from '../doctor-report.js';

const WARN: DoctorReportItem = {
  label: 'Memory plane drift',
  status: 'warn',
  message: 'plane=dual_legacy: native agent SoT written inside the window — ~/clawd/memory/2026-08-29.md',
  fix: 'Time-box dual_legacy: `shieldcortex config --memory-plane import_only` — dual_legacy is a migration escape, not steady state',
  fixWhen: 'the host contract and defended import have landed — until then this command raises the same finding to FAIL',
};

// formatDoctorReport returns lines, not a blob.
const renderLines = (items: DoctorReportItem[], opts = {}): string[] =>
  formatDoctorReport(items, { color: false, ...opts });
const render = (items: DoctorReportItem[], opts = {}): string =>
  renderLines(items, opts).join('\n');

describe('#441 — doctor prints the precondition, not just the command', () => {
  it('renders the condition and the command together', () => {
    const out = render([WARN]);
    expect(out).toMatch(/only when:/);
    expect(out).toMatch(/host contract and defended import/);
    expect(out).toMatch(/\$ shieldcortex config --memory-plane import_only/);
  });

  it('puts the condition ABOVE the runnable command', () => {
    // Order is the whole point: an operator copies the first bold `$` they see.
    // A caveat underneath is read only by someone who already hesitated.
    const lines = renderLines([WARN]);
    const cond = lines.findIndex((l) => l.includes('only when:'));
    const cmd = lines.findIndex((l) => l.includes('$ shieldcortex config --memory-plane import_only'));
    expect(cond).toBeGreaterThanOrEqual(0);
    expect(cmd).toBeGreaterThanOrEqual(0);
    expect(cond).toBeLessThan(cmd);
  });

  it('keeps the condition when a group is collapsed', () => {
    // Collapsing merges fixCommands across members; before #441 there was no
    // fixWhen to merge, so this path is exactly where a precondition would
    // silently vanish while the command it guards survived.
    const sibling: DoctorReportItem = { ...WARN, message: WARN.message + ' (second signal)' };
    const out = render([WARN, sibling], { collapse: true });
    expect(out).toMatch(/only when:/);
    expect(out).toMatch(/\$ shieldcortex config --memory-plane import_only/);
  });

  it('says nothing extra when a remedy has no precondition', () => {
    const plain: DoctorReportItem = {
      label: 'Hooks',
      status: 'warn',
      message: '1/4 installed',
      fix: 'Run `shieldcortex setup` to install the hooks',
    };
    expect(render([plain])).not.toMatch(/only when:/);
  });
});
