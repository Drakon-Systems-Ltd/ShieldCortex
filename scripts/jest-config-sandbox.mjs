// Jest setupFilesAfterEnv: sandbox the ShieldCortex config AND audit directories
// per worker.
//
// Why this exists
// ---------------
// `src/cloud/config.ts:getConfigDir()` defaults to `~/.shieldcortex` when
// `SHIELDCORTEX_CONFIG_DIR` is unset, and the defence pipeline reads the live
// config on every scan — `pipeline.ts` builds its config as
// `{ ...DEFAULT_DEFENCE_CONFIG, mode: getDefenceMode() }` when no explicit
// config is passed (which is how the memory-file scanner and the hook
// save-path call it). So a verdict (ALLOW / QUARANTINE / BLOCK) depends on the
// contents of a single on-disk file.
//
// Under Jest's default parallel workers every worker process — and the
// developer's real machine — shared that ONE `~/.shieldcortex/config.json`. A
// config write in one worker (e.g. `verify.test.ts` calling `setVerifyConfig`)
// raced a verdict read in another, so a fixture that should QUARANTINE
// intermittently read a half-written config and came back BLOCK. That is the
// cross-suite flake that repeatedly forced manual npm publishes (CI Node-20 leg
// failing while Node-22 passed on the identical commit, both passing in
// isolation and under `--runInBand`). It also clobbered the real user config.
//
// The fix: give every worker its own throwaway config dir. Workers no longer
// share a file, so the race cannot happen, and tests never touch the real
// `~/.shieldcortex`. Tests that need their own dir still override
// `SHIELDCORTEX_CONFIG_DIR` in their own `beforeEach` — that wins per-test.
import { mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const workerId = process.env.JEST_WORKER_ID || '1';
const sandboxDir = join(tmpdir(), 'shieldcortex-jest-config', `worker-${workerId}`);
mkdirSync(sandboxDir, { recursive: true });

// The same hazard, one directory over — and this one writes rather than reads.
//
// `plugins/openclaw/interceptor.ts:auditDir()` defaults to
// `~/.shieldcortex/audit` when `SHIELDCORTEX_AUDIT_DIR` is unset, and
// `writeAuditEntry()` appends an intercept row on every guarded call. The
// override has been honoured since d5fa817 (v4.47.39) — but honouring a
// variable nobody sets is not isolation. Ten suites set it in their own
// beforeEach; every other suite that reaches the interceptor appended
// FABRICATED intercept rows to the host operator's real security audit.
//
// Measured on a live host, 29 Aug 2026: 182 of 228 approval rows in
// `~/.shieldcortex/audit/realtime-2026-08-29.jsonl` landed in two minutes
// (09:41, 09:49) carrying the fixture command `npm install lodash` and session
// ids `sc-sess-A` / `sc-sess-B` / `sc-sess-approve`. That is 80% of a day's
// approvals, and it corrupted the very rate an operator reads when deciding
// whether the Action Guard is paging too often — a synthetic burst is
// indistinguishable from a real storm once it is in the file.
//
// Audit isolation must therefore be default-on, exactly like the config dir:
// opt-in isolation for a WRITE path is a footgun, because the cost of
// forgetting lands on the operator's forensics rather than on the test.
const auditSandboxDir = join(tmpdir(), 'shieldcortex-jest-audit', `worker-${workerId}`);
mkdirSync(auditSandboxDir, { recursive: true });

// Establish the sandbox immediately so any config read at test-file load time
// (a few suites capture the dir at module scope) sees it, not the real dir.
process.env.SHIELDCORTEX_CONFIG_DIR = sandboxDir;
process.env.SHIELDCORTEX_AUDIT_DIR = auditSandboxDir;

// Re-assert before every test. Several suites `delete process.env
// .SHIELDCORTEX_CONFIG_DIR` in their teardown — that pattern was written when
// the default was the real `~/.shieldcortex`, so a bare delete would otherwise
// drop the next test back onto the shared real file. This runs before any
// file-level `beforeEach`, so a suite that sets its own dir still overrides it.
beforeEach(() => {
  if (!process.env.SHIELDCORTEX_CONFIG_DIR) {
    process.env.SHIELDCORTEX_CONFIG_DIR = sandboxDir;
  }
  if (!process.env.SHIELDCORTEX_AUDIT_DIR) {
    process.env.SHIELDCORTEX_AUDIT_DIR = auditSandboxDir;
  }
});
