/**
 * Default firewall rule seeder.
 *
 * The `firewall_rules` table starts empty in production. The defence
 * pipeline's PATTERN_GROUPS catch most threats inline (instruction
 * injection, hidden instructions, etc.), but seeding the table with
 * built-in rules makes them visible in the dashboard and gives operators
 * a place to disable, edit, or extend them.
 *
 * Built-in rows are marked `built_in=1` and excluded from the user
 * `MAX_RULES=25` cap (see custom-rules/store.ts). They are always
 * evaluated — the `custom_firewall_rules` feature gate (graded free
 * since 4.47.0) applies only to user-added rules with `built_in=0`.
 *
 * Idempotent: running the seeder again is a no-op when built-in rules
 * are already present. Operators wanting to re-seed after a built-in
 * update should `DELETE FROM firewall_rules WHERE built_in = 1` first.
 */

import type Database from 'better-sqlite3';

interface BuiltInRule {
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
}

const BUILT_IN_RULES: BuiltInRule[] = [
  {
    name: 'builtin:instruction_injection',
    priority: 10,
    condition_type: 'regex',
    condition_value: '\\[SYSTEM:|<<SYS>>|\\[INST\\]|<\\|im_start\\|>|<\\|system\\|>|##SYSTEM##',
    action: 'quarantine',
  },
  {
    name: 'builtin:hidden_instruction',
    priority: 11,
    condition_type: 'regex',
    condition_value: 'ignore\\s+(all\\s+)?previous\\s+(instructions?|prompts?)|forget\\s+everything|disregard\\s+(all\\s+)?(previous|above|prior)|override\\s+(previous|all|system)',
    action: 'quarantine',
  },
  {
    name: 'builtin:imperative_tool_call',
    priority: 12,
    condition_type: 'regex',
    condition_value: '\\b(?:call|invoke|use)\\s+(?:the\\s+)?[A-Za-z][\\w-]*\\s+tool\\b|\\b(?:call|invoke|use)\\s+this\\s+tool\\s+now\\b',
    action: 'quarantine',
  },
  {
    name: 'builtin:memory_manipulation',
    priority: 15,
    condition_type: 'regex',
    condition_value: 'save\\s+(this\\s+)?to\\s+memory|remember\\s+this\\s+(instruction|command|rule)|store\\s+this\\s+instruction|inject\\s+(into\\s+)?memory',
    action: 'quarantine',
  },
  {
    name: 'builtin:command_injection',
    priority: 5,
    condition_type: 'regex',
    condition_value: '\\beval\\s*\\(|\\bexec\\s*\\(|\\bsystem\\s*\\(|\\bexecute\\s+(this\\s+)?(command|code|script)|\\b__import__\\s*\\(|\\bsubprocess\\b',
    action: 'quarantine',
  },
  {
    name: 'builtin:delimiter_attack',
    priority: 18,
    condition_type: 'regex',
    condition_value: '<\\/?(system|admin|root)\\s*>|<!--[\\s\\S]{0,200}?(instruction|command|system|ignore|inject|override)[\\s\\S]{0,200}?-->',
    action: 'quarantine',
  },
  {
    name: 'builtin:credential_leak_aws',
    priority: 1,
    condition_type: 'regex',
    condition_value: 'AKIA[0-9A-Z]{16}',
    action: 'block',
  },
  {
    name: 'builtin:credential_leak_jwt',
    priority: 2,
    condition_type: 'regex',
    condition_value: 'eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
    action: 'block',
  },
  {
    name: 'builtin:credential_leak_private_key',
    priority: 3,
    condition_type: 'regex',
    condition_value: '-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----',
    action: 'block',
  },
];

export function seedDefaultFirewallRules(db: Database.Database): void {
  // Confirm the column exists (older DBs may pre-date the migration).
  const cols = db.prepare("PRAGMA table_info(firewall_rules)").all() as { name: string }[];
  if (!cols.some(c => c.name === 'built_in')) return;

  const existing = db.prepare('SELECT COUNT(*) AS c FROM firewall_rules WHERE built_in = 1').get() as { c: number };
  if (existing.c > 0) return;

  const insert = db.prepare(`
    INSERT INTO firewall_rules (name, priority, condition_type, condition_value, action, enabled, built_in)
    VALUES (?, ?, ?, ?, ?, 1, 1)
  `);

  const txn = db.transaction((rules: BuiltInRule[]) => {
    for (const rule of rules) {
      insert.run(rule.name, rule.priority, rule.condition_type, rule.condition_value, rule.action);
    }
  });

  txn(BUILT_IN_RULES);
}

export function listBuiltInRuleNames(): string[] {
  return BUILT_IN_RULES.map(r => r.name);
}
