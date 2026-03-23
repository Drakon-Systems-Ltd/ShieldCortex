/**
 * Cortex CLI — shieldcortex cortex <subcommand>
 * Pro tier feature: systematic mistake learning + pre-flight checks.
 */

import { requireFeature } from '../license/gate.js';
import {
  capture, preflight, review, graduate, search, loadMistakes,
  type MistakeCategory, type MistakeSeverity,
} from './store.js';

const SEVERITY_ICON: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🟢',
};

const VALID_CATEGORIES: MistakeCategory[] = [
  'design', 'code', 'config', 'communication', 'judgement', 'process', 'data', 'security',
];

const VALID_SEVERITIES: MistakeSeverity[] = ['critical', 'high', 'medium', 'low'];

function printUsage(): void {
  console.log(`
  shieldcortex cortex <command> [options]

  Commands:
    capture     Log a mistake and extract a prevention rule
    preflight   Pre-task check against past mistakes
    review      Pattern analysis and weekly review
    graduate    Archive learned rules (30+ days, no recurrence)
    list        Browse mistake log
    stats       Summary counts and trends
    search      Full-text search across all entries

  Examples:
    shieldcortex cortex capture --category code --what "Guessed URLs" --why "Didn't use API" --rule "Always fetch handles from API"
    shieldcortex cortex preflight --task "deploy to Fly.io"
    shieldcortex cortex review
    shieldcortex cortex stats
  `);
}

function parseArgs(args: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--') && i + 1 < args.length) {
      result[args[i].slice(2)] = args[i + 1];
      i++;
    }
  }
  return result;
}

export async function handleCortexCommand(args: string[]): Promise<void> {
  requireFeature('cortex_learning');

  const subcommand = args[0];
  const subArgs = args.slice(1);
  const opts = parseArgs(subArgs);

  switch (subcommand) {
    case 'capture': {
      if (!opts.category || !opts.what || !opts.why || !opts.rule) {
        console.error('Required: --category, --what, --why, --rule');
        console.error(`Categories: ${VALID_CATEGORIES.join(', ')}`);
        process.exit(1);
      }
      if (!VALID_CATEGORIES.includes(opts.category as MistakeCategory)) {
        console.error(`Invalid category. Valid: ${VALID_CATEGORIES.join(', ')}`);
        process.exit(1);
      }
      const entry = capture({
        category: opts.category as MistakeCategory,
        severity: (opts.severity as MistakeSeverity) || 'medium',
        what: opts.what,
        why: opts.why,
        rule: opts.rule,
        tags: opts.tags ? opts.tags.split(',').map(t => t.trim()) : [],
        agent: opts.agent,
        taskContext: opts.context,
      });
      console.log(`✅ Captured mistake #${entry.id}: ${entry.what.slice(0, 60)}...`);
      console.log(`   Rule: ${entry.rule}`);
      console.log(`   Category: ${entry.category} | Severity: ${entry.severity}`);
      break;
    }

    case 'preflight': {
      if (!opts.task) {
        console.error('Required: --task "description of upcoming task"');
        process.exit(1);
      }
      const matches = preflight(opts.task);
      if (matches.length === 0) {
        console.log('✅ Pre-flight clear — no matching past mistakes found.');
        console.log(`   Task: ${opts.task.slice(0, 80)}`);
      } else {
        console.log(`⚠️  PRE-FLIGHT CHECK — ${matches.length} relevant past mistake(s):\n`);
        for (const { mistake: m } of matches) {
          const icon = SEVERITY_ICON[m.severity] || '⚪';
          console.log(`  ${icon} #${m.id} [${m.category}] ${m.rule}`);
          if (m.recurrences > 0) {
            console.log(`     ↳ Recurred ${m.recurrences}x — pay extra attention`);
          }
        }
        console.log(`\n  📋 Review these before proceeding with: ${opts.task.slice(0, 60)}`);
      }
      break;
    }

    case 'review': {
      const stats = review();
      if (stats.total === 0) {
        console.log('No mistakes logged yet. Use `shieldcortex cortex capture` to start.');
        return;
      }
      console.log('═══ CORTEX REVIEW ═══\n');
      console.log(`Total: ${stats.total} (${stats.active} active, ${stats.graduated} graduated)\n`);

      console.log('By category:');
      for (const [cat, count] of Object.entries(stats.byCategory).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${cat.padEnd(15)} ${'█'.repeat(count)} ${count}`);
      }

      console.log('\nActive by severity:');
      for (const sev of ['critical', 'high', 'medium', 'low']) {
        if (stats.bySeverity[sev]) {
          console.log(`  ${SEVERITY_ICON[sev]} ${sev}: ${stats.bySeverity[sev]}`);
        }
      }

      if (stats.repeatOffenders.length > 0) {
        console.log('\n⚠️  Repeat offenders:');
        for (const m of stats.repeatOffenders) {
          console.log(`  #${m.id} (${m.recurrences}x) ${m.rule.slice(0, 70)}`);
        }
      }

      if (stats.readyToGraduate.length > 0) {
        console.log(`\n✅ Ready to graduate (${stats.readyToGraduate.length} rules):`);
        for (const m of stats.readyToGraduate) {
          console.log(`  #${m.id} [${m.category}] ${m.rule.slice(0, 70)}`);
        }
      }
      break;
    }

    case 'graduate': {
      const count = graduate();
      console.log(`🎓 Graduated ${count} rule(s) — learned and archived.`);
      break;
    }

    case 'list': {
      let mistakes = loadMistakes();
      if (opts.category) mistakes = mistakes.filter(m => m.category === opts.category);
      if (opts.severity) mistakes = mistakes.filter(m => m.severity === opts.severity);
      if (opts.active === 'true') mistakes = mistakes.filter(m => m.status === 'active');

      if (mistakes.length === 0) {
        console.log('No matching mistakes.');
        return;
      }

      for (const m of mistakes) {
        const icon = SEVERITY_ICON[m.severity] || '⚪';
        const status = m.status === 'graduated' ? '📗' : '📕';
        console.log(`${status} #${m.id} ${icon} [${m.category}] ${m.what.slice(0, 50)}`);
        console.log(`   Rule: ${m.rule}`);
        if (m.tags.length) console.log(`   Tags: ${m.tags.join(', ')}`);
        console.log();
      }
      break;
    }

    case 'stats': {
      const stats = review();
      console.log(`📊 Cortex Stats`);
      console.log(`   Total: ${stats.total} | Active: ${stats.active} | Graduated: ${stats.graduated}`);
      console.log(`   Last 7 days: ${stats.recentCount}`);
      console.log(`   Repeat offenders: ${stats.repeatOffenders.length}`);
      break;
    }

    case 'search': {
      if (!opts.query) {
        console.error('Required: --query "search terms"');
        process.exit(1);
      }
      const results = search(opts.query);
      if (results.length === 0) {
        console.log(`No matches for '${opts.query}'`);
      } else {
        console.log(`🔍 ${results.length} match(es) for '${opts.query}':\n`);
        for (const m of results) {
          const icon = SEVERITY_ICON[m.severity] || '⚪';
          console.log(`  ${icon} #${m.id} [${m.category}] ${m.rule}`);
        }
      }
      break;
    }

    default:
      printUsage();
  }
}
