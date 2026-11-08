/**
 * #815 B — the keyless half of the tap endpoint.
 *
 * The root endpoint (src/cli/approve-tap.ts) checks the HMAC itself, then
 * spawns this file as the AGENT's user (uid/gid set by the spawn, a clean
 * environment, `--disable-sigusr1`) with the already-authenticated request on
 * stdin. This process never holds the approve secret, so a same-user agent
 * that signals, debugs or kills it gains nothing it could not already do to
 * its own grant store. It runs `applyAuthenticatedTap` — the nonce and grant
 * checks, all under the stores' own locks — and writes one JSON line.
 *
 * It refuses to act unless it really is running as the uid/gid the parent
 * named, and never as root (root-owned store files would lock the agent's
 * own guard out of them).
 */

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { applyAuthenticatedTap, type ApproveTapRequest, type TapVerifyOutcome } from './approve-tap.js';

export interface TapChildInput {
  request: ApproveTapRequest;
  home: string;
  expectUid: number;
  expectGid: number;
  grantTtlMs?: number;
}

export interface TapChildIds {
  uid: number;
  euid: number;
  gid: number;
  egid: number;
}

/** What the child answers the parent with. No grant body, no row. */
export type TapChildAnswer =
  | { ok: true; message: string; approver: string; actionId: string }
  | { ok: false; reason: string; message: string };

export function runTapChild(stdinText: string, ids: TapChildIds, now?: number): TapChildAnswer {
  let input: TapChildInput;
  try {
    input = JSON.parse(stdinText) as TapChildInput;
  } catch {
    return { ok: false, reason: 'malformed', message: 'The tap request was not in the expected form. Nothing was approved.' };
  }
  const wrongIds = !input || typeof input !== 'object'
    || !Number.isInteger(input.expectUid) || !Number.isInteger(input.expectGid)
    || input.expectUid === 0
    || ids.uid !== input.expectUid || ids.euid !== input.expectUid
    || ids.gid !== input.expectGid || ids.egid !== input.expectGid;
  if (wrongIds) {
    return { ok: false, reason: 'unwritable', message: 'The tap worker is not running as the agent\'s user. Nothing was approved.' };
  }
  if (typeof input.home !== 'string' || !input.home.startsWith('/')) {
    return { ok: false, reason: 'malformed', message: 'The tap request was not in the expected form. Nothing was approved.' };
  }
  const out: TapVerifyOutcome = applyAuthenticatedTap(input.request, {
    home: input.home,
    ...(now !== undefined ? { now } : {}),
    ...(typeof input.grantTtlMs === 'number' ? { grantTtlMs: input.grantTtlMs } : {}),
  });
  return out.ok
    ? { ok: true, message: out.message, approver: out.approver, actionId: out.actionId }
    : { ok: false, reason: out.reason, message: out.message };
}

function isMain(): boolean {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMain()) {
  const chunks: Buffer[] = [];
  let size = 0;
  process.stdin.on('data', (c: Buffer) => {
    size += c.length;
    if (size > 16_384) process.exit(2);
    chunks.push(c);
  });
  process.stdin.on('end', () => {
    const ids: TapChildIds = {
      uid: process.getuid?.() ?? -1,
      euid: process.geteuid?.() ?? -1,
      gid: process.getgid?.() ?? -1,
      egid: process.getegid?.() ?? -1,
    };
    let answer: TapChildAnswer;
    try {
      answer = runTapChild(Buffer.concat(chunks).toString('utf8'), ids);
    } catch {
      answer = { ok: false, reason: 'unwritable', message: 'The approvals store could not be written. Nothing was approved.' };
    }
    process.stdout.write(`${JSON.stringify(answer)}\n`);
  });
}
