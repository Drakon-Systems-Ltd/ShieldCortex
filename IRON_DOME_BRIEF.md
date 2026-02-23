# Iron Dome Integration Brief

## Goal
Add Iron Dome as a new module in ShieldCortex's defence layer. It protects agent BEHAVIOUR (instruction gating, action approval, injection scanning) while the existing defence layer protects agent MEMORY.

## What to Build

### 1. New module: `src/defence/iron-dome/`

```
src/defence/iron-dome/
├── index.ts           # Main exports
├── gateway.ts         # Instruction gateway control — validate if a channel is trusted
├── action-gate.ts     # External action gating — check if action needs approval
├── injection-scanner.ts  # Prompt injection detection (port scan.py logic to TypeScript)
├── pii-guard.ts       # PII protection rules
├── kill-switch.ts     # Kill phrase handling
├── config.ts          # IronDomeConfig type + defaults
├── audit.ts           # Iron Dome specific audit logging (uses existing audit system)
└── __tests__/
    ├── gateway.test.ts
    ├── injection-scanner.test.ts
    ├── action-gate.test.ts
    └── pii-guard.test.ts
```

### 2. Key interfaces

```typescript
interface IronDomeConfig {
  enabled: boolean;
  trustedChannels: string[];          // e.g. ['telegram', 'terminal']
  killPhrase: string;                 // e.g. 'full stop'
  requireApproval: string[];          // action types needing approval
  autoApprove: string[];              // action types auto-approved
  piiRules: {
    neverOutput: string[];            // categories to never show
    aggregatesOnly: string[];         // categories: totals only
  };
  subAgentRestrictions: {
    blockedOperations: string[];
    sanitiseContext: boolean;
  };
  profile?: 'school' | 'enterprise' | 'personal' | 'paranoid';
}

// Pre-built profiles
const PROFILES = {
  school: { /* GDPR strict, pupil data locked */ },
  enterprise: { /* financial protection, compliance */ },
  personal: { /* lighter touch */ },
  paranoid: { /* everything requires approval */ }
};
```

### 3. CLI commands

Add to existing CLI:
```bash
shieldcortex iron-dome activate [--profile school|enterprise|personal|paranoid]
shieldcortex iron-dome status
shieldcortex iron-dome deactivate
shieldcortex iron-dome scan --text "..."
shieldcortex iron-dome scan --file <path>
shieldcortex iron-dome audit [--tail] [--search <term>] [--date <date>]
```

### 4. MCP tools (add to existing MCP server)

```
iron_dome_status     — Check if Iron Dome is active, show config summary
iron_dome_scan       — Scan text for injection patterns
iron_dome_check      — Check if an action is allowed (gateway + action gate)
iron_dome_activate   — Activate Iron Dome with a profile
```

### 5. Library exports (add to src/lib.ts)

```typescript
export {
  activateIronDome,
  deactivateIronDome,
  getIronDomeStatus,
  isChannelTrusted,
  isActionAllowed,
  scanForInjection,
  checkPII,
  handleKillPhrase,
  IRON_DOME_PROFILES,
  DEFAULT_IRON_DOME_CONFIG,
} from './defence/iron-dome/index.js';
```

### 6. Injection Scanner

Port the Python scan.py logic to TypeScript. Detection categories:
- `instruction_override` — "ignore previous", "disregard", "forget your instructions"
- `authority_claim` — "I am the admin", "as the system operator", impersonation
- `credential_extraction` — requesting passwords, keys, tokens, secrets
- `urgency_secrecy` — "do this now", "don't tell anyone", "delete the logs"
- `fake_system_message` — `[System]`, `[Admin]`, `<<OVERRIDE>>` tags
- `encoding_tricks` — base64 encoded instructions, unicode obfuscation

Each detection returns: `{ category, pattern, severity: 'low'|'medium'|'high'|'critical', match }`

### 7. Integration with existing systems

- Use existing `logAudit()` for audit logging (add 'iron-dome' as a category)
- Use existing `DefenceConfig` pattern — extend it with `ironDome?: IronDomeConfig`
- Use existing trust scoring — Iron Dome gateway builds on trust concepts
- Dashboard: Add Iron Dome status panel (future — not in this PR)

### 8. Destructive Action Confirmation Protocol

3-tier classification system that gates destructive actions before they execute.

```
RED    — ALWAYS requires explicit user confirmation (irreversible/destructive)
AMBER  — Announce before proceeding (should be visible, but not blocking)
GREEN  — Free to execute silently (safe, read-only, or low-risk)
```

**Default RED actions:** `rm`, `rmdir`, `delete`, `drop`, `truncate`, `purge`, `wipe`, `shred`, `destroy`, `remove_cron`, `disable_service`, `stop_service`, `revoke_token`, `rotate_credentials`, `force_push`, `delete_branch`, `modify_firewall`, `modify_netplan`, `modify_systemd`, `modify_dns`, `bulk_email_delete`, `chmod_recursive`, `chown_recursive`

**Default AMBER actions:** `edit_file`, `install_package`, `update_package`, `create_cron`, `restart_service`, `modify_config`, `database_migrate`

**Default GREEN actions:** `read_file`, `write_new_file`, `git_commit`, `git_push`, `run_report`, `web_search`, `web_fetch`, `create_directory`, `list_files`

**Key behaviours:**
- Unknown/unclassified actions default to **AMBER** (safe default)
- RED takes priority when an action matches multiple tiers
- Matching is case-insensitive and uses partial (contains) matching
- When Iron Dome is disabled, all actions resolve to GREEN
- Each profile (school/enterprise/personal/paranoid) has its own tier lists
- RED classifications are audit-logged via `logIronDomeAudit`

**API:**
```typescript
import { classifyAction, requiresConfirmation, requiresAnnouncement } from './confirmation-gate.js';

classifyAction('rm -rf /tmp', config);
// → { tier: 'red', action: 'rm -rf /tmp', description: '...', reversible: false }

requiresConfirmation('delete', config);  // true (RED)
requiresAnnouncement('edit_file', config); // true (RED or AMBER)
```

**New types:** `ConfirmationTier`, `ConfirmationResult`
**New config field:** `confirmationProtocol: { red: string[], amber: string[], green: string[] }`

## Rules
- TypeScript strict, ESM
- Tests for scanner, gateway, action gate, and confirmation gate (these are security-critical)
- Don't break existing exports or tests
- Run `npm run build` and `npm test` before committing
- Commit with descriptive message

## Reference
- Existing scanner logic: ~/clawd/skills/iron-dome/scripts/scan.py (Python — port to TS)
- Existing defence types: src/defence/types.ts
- Existing audit: src/defence/audit/
