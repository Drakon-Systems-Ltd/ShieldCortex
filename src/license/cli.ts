/**
 * CLI commands for license management.
 *
 * shieldcortex license activate <key>
 * shieldcortex license status
 * shieldcortex license deactivate
 */

import { activateLicense, deactivateLicense, getLicense, getLicenseFile } from './store.js';
import { listFeatures } from './gate.js';
import { validateOnceNow } from './validate.js';
import type { LicenseTier } from './keys.js';

const bold = '\x1b[1m';
const reset = '\x1b[0m';
const green = '\x1b[32m';
const red = '\x1b[31m';
const yellow = '\x1b[33m';
const cyan = '\x1b[36m';
const dim = '\x1b[2m';

function tierBadge(tier: LicenseTier): string {
  switch (tier) {
    case 'enterprise': return `${bold}${cyan}Enterprise${reset}`;
    case 'team': return `${bold}${cyan}Team${reset}`;
    case 'pro': return `${bold}${green}Pro${reset}`;
    default: return `${dim}Free${reset}`;
  }
}

// ── Activate ─────────────────────────────────────────────

async function handleActivate(key: string | undefined): Promise<void> {
  if (!key) {
    console.error('Usage: shieldcortex license activate <key>');
    console.error('');
    console.error('Enterprise licences: sales@drakonsystems.com');
    process.exit(1);
  }

  try {
    const info = activateLicense(key);

    console.log(`\n${bold}Licence Activated${reset}`);
    console.log('═'.repeat(40));
    console.log(`  Tier:    ${tierBadge(info.tier)}`);
    console.log(`  Email:   ${info.email}`);
    if (info.expiresAt) {
      console.log(`  Expires: ${info.expiresAt.toLocaleDateString()} (${info.daysUntilExpiry} days)`);
    }

    // Run one-time online validation
    console.log(`\n  ${dim}Validating online...${reset}`);
    const status = await validateOnceNow();
    if (status === 'valid') {
      console.log(`  ${green}✓${reset} Licence confirmed active`);
    } else if (status === 'revoked') {
      console.log(`  ${red}✗${reset} Licence has been revoked`);
    } else {
      console.log(`  ${yellow}!${reset} Could not reach validation server (licence works offline)`);
    }

    // Show unlocked features
    console.log(`\n${bold}Features:${reset}`);
    const features = listFeatures();
    for (const f of features) {
      const icon = f.enabled ? `${green}[✓]${reset}` : `${dim}[ ]${reset}`;
      const tierLabel = f.enabled ? '' : ` ${dim}(${f.requiredTier})${reset}`;
      console.log(`  ${icon} ${f.description}${tierLabel}`);
    }
    console.log();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\n${red}Activation failed:${reset} ${message}`);
    process.exit(1);
  }
}

// ── Status ───────────────────────────────────────────────

function handleStatus(): void {
  const info = getLicense();
  const file = getLicenseFile();

  console.log(`\n${bold}ShieldCortex Licence${reset}`);
  console.log('═'.repeat(40));

  if (info.valid) {
    // Paid license active — show full license info
    console.log(`  Tier:       ${tierBadge(info.tier)}`);
    console.log(`  Email:      ${info.email}`);
    if (info.expiresAt) {
      const daysStr = info.daysUntilExpiry !== null && info.daysUntilExpiry > 0
        ? `(${info.daysUntilExpiry} days remaining)`
        : info.daysUntilExpiry !== null && info.daysUntilExpiry <= 0
          ? `${red}(expired)${reset}`
          : '';
      console.log(`  Expires:    ${info.expiresAt.toLocaleDateString()} ${daysStr}`);
    }

    if (file?.lastValidatedAt) {
      console.log(`  Validated:  ${new Date(file.lastValidatedAt).toLocaleString()}`);
    }
    if (file?.validationStatus) {
      const statusColor = file.validationStatus === 'valid' ? green :
                          file.validationStatus === 'revoked' ? red : yellow;
      console.log(`  Status:     ${statusColor}${file.validationStatus}${reset}`);
    }
  } else {
    // No licence — Free tier includes every local feature
    console.log(`  Tier:       ${tierBadge('free')}`);
    console.log(`\n  All local features are included on the Free tier.`);
    console.log(`  Enterprise (cloud replication, teams, fleets): ${cyan}sales@drakonsystems.com${reset}`);
    console.log(`  Have a key? shieldcortex license activate <key>\n`);
    return;
  }

  console.log(`\n${bold}Features:${reset}`);
  const features = listFeatures();
  for (const f of features) {
    const icon = f.enabled ? `${green}[✓]${reset}` : `${dim}[ ]${reset}`;
    const tierLabel = f.enabled ? '' : ` ${dim}(${f.requiredTier})${reset}`;
    console.log(`  ${icon} ${f.description}${tierLabel}`);
  }
  console.log();
}

// ── Deactivate ───────────────────────────────────────────

function handleDeactivate(): void {
  deactivateLicense();
  console.log(`\n${bold}Licence deactivated.${reset}`);
  console.log(`All features reverted to Free tier.\n`);
}

// ── Router ───────────────────────────────────────────────

export async function handleLicenseCommand(args: string[]): Promise<void> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'activate':
      await handleActivate(args[1]);
      break;
    case 'status':
      handleStatus();
      break;
    case 'deactivate':
      handleDeactivate();
      break;
    default:
      console.log(`\n${bold}ShieldCortex Licence${reset}`);
      console.log('');
      console.log('  shieldcortex license activate <key>  Activate a licence key');
      console.log('  shieldcortex license status          Show current licence');
      console.log('  shieldcortex license deactivate      Remove licence');
      console.log('');
      console.log(`  Enterprise licences: ${cyan}sales@drakonsystems.com${reset}`);
      console.log();
      break;
  }
}
