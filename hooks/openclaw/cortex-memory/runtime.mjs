import { execFile } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import fs from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Opt-out for the cortex-memory hook's mutating self-heal (#108). Exported so
// the hook, the docs test, and the unit tests all name the flag once.
export const SELF_HEAL_SKIP_ENV = "SHIELDCORTEX_SKIP_SELF_HEAL";

/**
 * Is the hook's self-heal allowed to write? (#108)
 *
 * Pure predicate over the loaded config plus the environment, so the gate is
 * unit-testable without touching a filesystem. Disabled by
 * SHIELDCORTEX_SKIP_SELF_HEAL=1 or `"selfHeal": false` in
 * ~/.shieldcortex/config.json. Every other input — including a missing,
 * empty, or unreadable config — leaves it ENABLED, so the default preserves
 * the behaviour installs had before 4.47.12.
 */
export function isSelfHealEnabled(config, env = process.env) {
  if (env?.[SELF_HEAL_SKIP_ENV] === "1") return false;
  return config?.selfHeal !== false;
}

/**
 * The strict fail-closed posture over a parsed config (#878). Mirrors
 * `applyStrictFailClosedPosture` in src/defence/iron-dome/policy-lock.ts key
 * for key — Action Guard on + enforcing, no auto-approve, broker off, no
 * reviewed-script exemptions, no readiness gate, defenceMode strict, and the
 * deprecated `interceptor.actionGuard` alias stripped of those keys so its
 * per-key gap-fill (#209) cannot bring one back. This file is copied into
 * OpenClaw hook directories and cannot import dist.
 */
function strictFailClosedPosture(raw) {
  const isBlock = (v) => v && typeof v === "object" && !Array.isArray(v);
  const out = { ...raw };
  const guard = isBlock(out.actionGuard) ? { ...out.actionGuard } : {};
  guard.enabled = true;
  guard.enforce = true;
  guard.autoApprove = [];
  guard.broker = { ...(isBlock(guard.broker) ? guard.broker : {}), enabled: false };
  guard.reviewedScripts = [];
  delete guard.readinessGate;
  out.actionGuard = guard;
  out.defenceMode = "strict";
  if (isBlock(out.interceptor) && isBlock(out.interceptor.actionGuard)) {
    const alias = { ...out.interceptor.actionGuard };
    for (const key of ["enabled", "enforce", "autoApprove", "broker", "reviewedScripts", "readinessGate"]) delete alias[key];
    out.interceptor = { ...out.interceptor, actionGuard: alias };
  }
  return out;
}

// #878 r5: the signature verifier for a SYMLINKED config.json. This file is
// copied alone into OpenClaw hook directories and cannot import
// scripts/lib/config-authenticity.mjs, so the region between the markers is a
// byte-identical copy of that module's (a test fails on drift). It recomputes
// the HMAC exactly as src's checkConfigIntegrity does; presence of a `_sig`
// string or a `.config-sig` file is not a signature.
// BEGIN config-signature-verdict (#878 r5; pinned copy in hooks/openclaw/cortex-memory/runtime.mjs)
/**
 * checkConfigIntegrity's verdict (src/cloud/config.ts) over bytes and sidecars
 * already read: the same key use (the trimmed `.integrity-key` text as the HMAC
 * key), the same embedded body (the object minus `_sig`,
 * `JSON.stringify(rest, null, 2)`), the same legacy scheme (a `.config-sig`
 * HMAC over the exact file bytes, used whenever `_sig` is not a string), the
 * same self-heal rule and a constant-time compare.
 *
 * `key`: the trimmed key text, or null when it is missing, unreadable or empty
 * (an empty key fails strict here; src's read-only inspector reads it the same
 * way). `legacySig`: undefined when `.config-sig` does not exist, null when it
 * exists but cannot be read (a directory, permissions), else its trimmed text.
 * Returns `valid`, `self-heal`, `tampered` or `unsigned` (no signature at all).
 */
export function configSignatureVerdict({ parsed, raw, key, legacySig }) {
  const equalHex = (stored, computed) => {
    const a = Buffer.from(stored, "utf-8");
    const b = Buffer.from(computed, "utf-8");
    return a.length === b.length && timingSafeEqual(a, b);
  };
  try {
    const sign = (body) => {
      if (typeof key !== "string" || key.length === 0) throw new Error("no integrity key");
      return createHmac("sha256", key).update(body, "utf-8").digest("hex");
    };
    if (typeof parsed._sig === "string") {
      const rest = { ...parsed };
      delete rest._sig;
      if (equalHex(parsed._sig, sign(JSON.stringify(rest, null, 2)))) return "valid";
      if (typeof legacySig === "string" && equalHex(legacySig, sign(raw))) return "self-heal";
      return "tampered";
    }
    if (legacySig === undefined) return "unsigned";
    if (typeof legacySig !== "string") return "tampered";
    return equalHex(legacySig, sign(raw)) ? "valid" : "tampered";
  } catch {
    return "tampered";
  }
}

/** A verdict under which a symlinked config.json's own values are in force. */
export function verdictAuthenticates(verdict) {
  return verdict === "valid" || verdict === "self-heal";
}
// END config-signature-verdict

export function createOpenClawRuntime({
  logPrefix = "[shieldcortex]",
  configPath = path.join(process.env.SHIELDCORTEX_CONFIG_DIR?.trim() || path.join(homedir(), ".shieldcortex"), "config.json"),
} = {}) {
  // The last read of config.json that describes the entry it was taken from:
  // `{ key, raw, text }` — the entry's identity key (configIdentityKey), the
  // object its bytes parsed to (null: no config — absent, blank, malformed,
  // non-object, unreadable) and those bytes. Replaced whole, only after the
  // entry was seen unchanged around the read (loadShieldConfigExclusive).
  let lastRead = null;
  // The effective object for `lastRead.raw` (the strict view when the entry is
  // an unsigned link) and the link verdict it was built under; null until built.
  let shieldConfig = null;
  let shieldConfigLinkedUnsigned = false;
  // The posture this runtime last established from config.json: the effective
  // object (strict view included) of the last read whose bytes parsed to an
  // object. Not a cache — see holdEstablishedPosture.
  let establishedShieldConfig = null;
  // The answer while nothing is established: one object, so its identity is
  // stable across calls and the plugin does not re-merge on every call.
  let defaultShieldConfig = null;
  let resolvedServerCmd = null;
  let lastCallErrorType = null;

  // #878: is config.json a symbolic link whose bytes no signature
  // authenticates? Mirrors src/cloud/config.ts (readRawConfigStateUnlocked →
  // readRawConfigState): the read layer never adopts (signs) or self-heals
  // through a link, so a linked file is in force only when an existing
  // signature authenticates it — r5: the HMAC recomputed with the local
  // `.integrity-key` (configSignatureVerdict above), never the mere presence of
  // a `_sig` string or a `.config-sig` file, which the link's target or a
  // stray sidecar can supply. Anything else is held at the strict fail-closed
  // posture — never Guard off. A regular file is still taken as plain JSON
  // (no HMAC check on it, #509). A dangling link has no bytes to take a
  // posture from: `{}` on a first read, the established posture afterwards
  // (holdEstablishedPosture), as src reads it. Same rule, same verifier:
  // scripts/pre-tool-hook.mjs and src/setup/openclaw-selfcheck.ts, through
  // scripts/lib/config-authenticity.mjs.
  async function readSidecar(file) {
    try {
      await fs.stat(file);
    } catch {
      return undefined;
    }
    try {
      return (await fs.readFile(file, "utf-8")).trim();
    } catch {
      return null;
    }
  }

  // `entry`: the lstat of config.json taken by this load (configEntrySnapshot),
  // so the verdict is about the same entry the bytes were read from. No lstat
  // of its own: a second lstat that failed used to answer "not a link" and
  // hand back the target's own values (#983 review).
  async function linkedUnauthenticated(entry, parsed, raw) {
    if (!entry.isSymbolicLink()) return false;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const dir = path.dirname(configPath);
    const key = await readSidecar(path.join(dir, ".integrity-key"));
    const verdict = configSignatureVerdict({
      parsed,
      raw,
      key: typeof key === "string" ? key : null,
      legacySig: await readSidecar(path.join(dir, ".config-sig")),
    });
    return !verdictAuthenticates(verdict);
  }

  // #878 r4: the cache key for the bytes and their parse status. mtime alone
  // was not enough: a warm runtime swapped from a signed (or empty, malformed,
  // array) file to an unsigned link with the same mtime kept serving the OLD
  // parsed object, so the link verdict judged the old bytes and Guard stayed off
  // while a fresh runtime and src held strict. The key is the identity
  // (dev, ino, size, mtime, ctime — ns, so a utimes-restored mtime is no cover;
  // user space cannot set ctime) of the config.json ENTRY (lstat: file or link,
  // and which link), the link text, and the identity of the file the link
  // FOLLOWS to (stat). Any change to any of them drops the cached bytes, parse
  // status and posture and re-reads before the unsigned-link verdict is taken;
  // a re-read that finds no config holds the established posture instead of
  // reading `{}` (holdEstablishedPosture).
  // Keep in step with src/cloud/config.ts (fileIdentity, cachedRawConfigLinked).
  async function configIdentityKey(entry) {
    const id = (st) => `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`;
    if (!entry.isSymbolicLink()) return `entry:${id(entry)}`;
    let text = "";
    try {
      text = await fs.readlink(configPath);
    } catch {}
    let target;
    try {
      target = id(await fs.stat(configPath, { bigint: true }));
    } catch (err) {
      target = `dangling:${err?.code ?? "?"}`;
    }
    return `link:${id(entry)}|${JSON.stringify(text)}|${target}`;
  }

  // The key of a config.json ENTRY that does not exist.
  const ABSENT_ENTRY_KEY = "absent:ENOENT";

  /**
   * One lstat of the config.json ENTRY (#983 review):
   * - `{ state: "absent", key }`: ENOENT — there is no config.json;
   * - `{ state: "unknown" }`: any other lstat error (EIO, EACCES, ...) —
   *   whether the entry exists, and whether it is a link, is unknown. No key:
   *   nothing is cached under a fault, so a change that lands while it lasts
   *   is seen once lstat works again;
   * - `{ state: "present", entry, key }`: its lstat and identity key.
   */
  async function configEntrySnapshot() {
    let entry;
    try {
      entry = await fs.lstat(configPath, { bigint: true });
    } catch (err) {
      return err?.code === "ENOENT" ? { state: "absent", key: ABSENT_ENTRY_KEY } : { state: "unknown" };
    }
    return { state: "present", entry, key: await configIdentityKey(entry) };
  }

  // Plain JSON. The CLI HMAC-signs this file, but a REGULAR file's signature
  // is not verified on this path: callers must not describe it as signed
  // (#509 r8). Only a symlinked file's is, and only to decide whether it is
  // held strict (#878 r5, linkedUnauthenticated); the text is kept because the
  // legacy signature covers the exact bytes. `null`, an array or a scalar
  // parses but is not a config: malformed, as src reads it.
  async function readConfigBytes() {
    let rawShieldConfigText = "";
    let rawShieldConfig = null;
    try {
      rawShieldConfigText = await fs.readFile(configPath, "utf-8");
      rawShieldConfig = JSON.parse(rawShieldConfigText);
    } catch {
      rawShieldConfig = null;
    }
    if (!rawShieldConfig || typeof rawShieldConfig !== "object" || Array.isArray(rawShieldConfig)) {
      return { raw: null, text: "" };
    }
    return { raw: rawShieldConfig, text: rawShieldConfigText };
  }

  /**
   * The answer for a load of config.json that yields no config — blank or
   * whitespace, malformed, non-object JSON, unreadable (EIO, EACCES, EISDIR, a
   * dangling link), or an entry that cannot be lstat'd (#983 review): the
   * posture this runtime established, HELD, or `{}` when it has established
   * none. Mirrors src/cloud/config.ts holdEstablished (#981): a newly observed
   * error or blank state never relaxes a posture already in force. The held
   * object is the established one itself, so its identity does not change and
   * the plugin neither re-merges nor rebuilds the interceptor
   * (plugins/openclaw/index.ts loadConfig / initInterceptor). Before this,
   * #878 r4's identity key (ctime included) missed on an in-place blank that
   * restored the mtime, and the re-read answered `{}`: Action Guard off at the
   * gate, where v5.17.1's mtime-only cache had answered with the enforcing
   * object.
   *
   * Only an absent ENTRY (lstat ENOENT) clears it: the documented move-aside
   * recovery, and a fresh install reads exactly as before.
   */
  function holdEstablishedPosture() {
    if (establishedShieldConfig) return establishedShieldConfig;
    if (!defaultShieldConfig) defaultShieldConfig = {};
    return defaultShieldConfig;
  }

  // How many times a load re-reads when config.json changes under its read
  // before it holds instead (the next load tries again).
  const READ_ATTEMPTS = 3;

  /**
   * One load, with no other load in flight (loadShieldConfig). Identity-gated
   * cache: re-read whenever the config entry or its target changes, so
   * dashboard / CLI toggles take effect on the next event without an OpenClaw
   * gateway restart.
   *
   * #983 review: the bytes and the verdict over them come from one entry. The
   * entry is lstat'd before the read and again after it; the bytes are cached
   * and judged only when both lstats succeed with the same key, and the link
   * verdict uses that lstat. An lstat that fails with anything but ENOENT
   * takes nothing from the bytes: it holds (holdEstablishedPosture). Before,
   * an lstat error keyed `absent:EIO`, re-read the bytes, and a second lstat
   * that failed too answered "not a link" — the unsigned link's own Guard-off
   * values became the established posture, and a later blank held them.
   */
  async function loadShieldConfigExclusive() {
    for (let attempt = 1; ; attempt += 1) {
      const before = await configEntrySnapshot();
      if (before.state === "unknown") return holdEstablishedPosture();
      if (before.state === "absent") {
        // config.json is gone: the established posture goes with it.
        lastRead = { key: before.key, raw: null, text: "" };
        shieldConfig = null;
        establishedShieldConfig = null;
        return holdEstablishedPosture();
      }
      if (lastRead?.key !== before.key) {
        const { raw, text } = await readConfigBytes();
        const after = await configEntrySnapshot();
        if (after.state === "unknown") return holdEstablishedPosture();
        if (after.key !== before.key) {
          // Changed under the read: these bytes may not be that entry's.
          if (attempt < READ_ATTEMPTS) continue;
          return holdEstablishedPosture();
        }
        lastRead = { key: before.key, raw, text };
        shieldConfig = null;
      }
      // No bytes to judge, so no link verdict either: the held posture (or
      // `{}`) stands until the key moves again.
      if (lastRead.raw === null) return holdEstablishedPosture();

      // The returned object's identity changes only when the bytes or the link
      // verdict do: the plugin re-merges on identity change. The verdict runs
      // on every load: a sidecar (.integrity-key, .config-sig) can change
      // without the entry's key moving.
      const linked = await linkedUnauthenticated(before.entry, lastRead.raw, lastRead.text);
      if (!shieldConfig || linked !== shieldConfigLinkedUnsigned) {
        shieldConfigLinkedUnsigned = linked;
        shieldConfig = linked ? strictFailClosedPosture(lastRead.raw) : lastRead.raw;
      }
      establishedShieldConfig = shieldConfig;
      return shieldConfig;
    }
  }

  // #983 review: loads run one at a time, each after the previous one has
  // finished. Two tool calls read config.json together on a busy gateway;
  // with interleaved loads one could judge the previous file's bytes against
  // the current entry (an unsigned link's Guard-off values taken as a regular
  // file's) and make them the established posture, or put back the posture a
  // removal had just cleared. A load never calls back into this queue.
  let loadQueue = Promise.resolve();
  function loadShieldConfig() {
    const load = loadQueue.then(loadShieldConfigExclusive);
    loadQueue = load.then(
      () => undefined,
      () => undefined,
    );
    return load;
  }

  function isOpenClawAutoMemoryEnabled(config) {
    return config?.openclawAutoMemory === true;
  }

  function classifyCallError(err) {
    if (err.killed || err.code === "ETIMEDOUT" || err.signal === "SIGTERM") return "timeout";
    if (/ENOENT|not found|command not found/i.test(err.message || "")) return "not-found";
    if (/mcporter/i.test(err.message || "")) return "mcporter";
    return "unknown";
  }

  async function resolveServerCmd() {
    if (resolvedServerCmd) return resolvedServerCmd;

    try {
      const config = await loadShieldConfig();
      if (config?.binaryPath) {
        await fs.access(config.binaryPath);
        resolvedServerCmd = config.binaryPath;
        console.log(`${logPrefix} Using configured binary: ${config.binaryPath}`);
        return resolvedServerCmd;
      }
    } catch {}

    try {
      const { execFileSync } = await import("node:child_process");
      const bin = execFileSync("which", ["shieldcortex"], {
        encoding: "utf-8",
        timeout: 3000,
      }).trim();
      if (bin) {
        resolvedServerCmd = bin;
        console.log(`${logPrefix} Using global install: ${bin}`);
        return resolvedServerCmd;
      }
    } catch {}

    resolvedServerCmd = "npx -y shieldcortex";
    console.log(`${logPrefix} Falling back to npx -y shieldcortex (slow path)`);
    return resolvedServerCmd;
  }

  // ==================== CHUNKER WRAPPER RESOLUTION ====================
  //
  // The OpenClaw hook extracts memories with the SAME hardened chunker the
  // Claude-Code side uses, loaded from the resolved local install. We resolve
  // the package root from the server binary (NOT by opening any DB), then
  // dynamic-import the PURE wrapper (no native deps). Persistence still goes
  // through callCortex's mcporter shell-out — never via a native DB handle in
  // this long-lived process.

  /**
   * Resolve the ShieldCortex package root from the resolved server command.
   * Returns null when there is no resolvable local install (npx fallback).
   * @returns {Promise<string|null>}
   */
  async function resolvePackageRoot() {
    const cmd = await resolveServerCmd();
    if (!cmd || cmd.startsWith("npx")) return null; // no local install
    const real = await fs.realpath(cmd).catch(() => cmd); // .../dist/index.js
    return path.resolve(path.dirname(real), ".."); // -> package root
  }

  let _openClawExtract = null;
  let _openClawExtractTried = false;

  /**
   * Dynamic-import the pure chunker wrapper from the resolved package root.
   * Cached after the first attempt. Returns null on any failure (no local
   * install, missing file, import error) — callers must treat null as
   * "skip auto-capture", NOT as a reason to fall back to a legacy high-salience
   * path.
   * @returns {Promise<{ extractSessionMemories: Function, extractKeywordMemory: Function }|null>}
   */
  async function loadOpenClawExtract() {
    if (_openClawExtract) return _openClawExtract;
    if (_openClawExtractTried) return _openClawExtract; // null, don't retry every event
    _openClawExtractTried = true;

    try {
      const root = await resolvePackageRoot();
      if (!root) return null;

      const wrapperPath = path.join(root, "scripts", "lib", "openclaw-extract.mjs");
      await fs.access(wrapperPath);

      // Absolute file URL — required so jiti / the copied hook resolves it
      // regardless of the hook's own on-disk location.
      const mod = await import(pathToFileURL(wrapperPath).href);
      if (typeof mod?.extractSessionMemories !== "function" || typeof mod?.extractKeywordMemory !== "function") {
        return null;
      }

      _openClawExtract = {
        extractSessionMemories: mod.extractSessionMemories,
        extractKeywordMemory: mod.extractKeywordMemory,
        extractSessionMemoriesWithDistill: typeof mod.extractSessionMemoriesWithDistill === "function"
          ? mod.extractSessionMemoriesWithDistill
          : null,
        // L2 candidate screen. Optional: an older installed package has no such
        // export, and its absence must mean "no screen" (today's behaviour),
        // never a hook that refuses every capture.
        loadMemoryCandidateScreen: typeof mod.loadMemoryCandidateScreen === "function"
          ? mod.loadMemoryCandidateScreen
          : null,
      };
      return _openClawExtract;
    } catch {
      return null;
    }
  }

  async function callCortex(tool, args = {}, options = { retries: 0, timeout: 15000 }) {
    const serverCmd = await resolveServerCmd();

    return new Promise((resolve) => {
      // Pass arguments as a single `--args <json>` payload, NOT as per-key
      // `key:value` flags. The old form did `String(value).replace(/'/g, "''")`
      // — SQL-style apostrophe doubling — on each value, which mangled saved
      // memory content (an apostrophe in "it's" became "it''s" and was stored
      // literally; this is a key:value CLI flag, not a bound SQL param, so no
      // such escaping should ever happen). A JSON payload also round-trips
      // colons, spaces, and newlines in content without the `key:value`
      // splitter misreading them. execFile passes argv elements directly (no
      // shell), so the JSON string needs no further quoting/escaping.
      const cmdArgs = ["mcporter", "call", "--stdio", serverCmd, tool, "--args", JSON.stringify(args)];

      let attempts = 0;
      const maxAttempts = (options.retries || 0) + 1;

      function attempt() {
        attempts++;
        execFile("npx", cmdArgs, {
          timeout: options.timeout || 15000,
          maxBuffer: 256 * 1024,
        }, (err, stdout) => {
          if (err) {
            const isTimeout = err.killed || err.code === "ETIMEDOUT" || err.signal === "SIGTERM";
            const errorType = isTimeout ? "TIMEOUT" : "ERROR";

            if (attempts < maxAttempts) {
              console.warn(`${logPrefix} ${errorType} on ${tool} (attempt ${attempts}/${maxAttempts}), retrying...`);
              setTimeout(attempt, 1000);
              return;
            }

            const category = classifyCallError(err);
            if (category !== lastCallErrorType) {
              lastCallErrorType = category;
              switch (category) {
                case "timeout":
                  console.warn(`${logPrefix} ShieldCortex call timed out (15s). Memory may be under heavy load.`);
                  break;
                case "not-found":
                  console.warn(`${logPrefix} ShieldCortex binary not found. Run: npm install -g shieldcortex`);
                  break;
                case "mcporter":
                  console.warn(`${logPrefix} mcporter failed to reach ShieldCortex MCP server. Is it configured?`);
                  break;
                default:
                  console.warn(`${logPrefix} ShieldCortex call failed: ${err.message}`);
              }
            }
            resolve(null);
            return;
          }

          resolve(stdout?.trim() || null);
        });
      }

      attempt();
    });
  }

  return {
    callCortex,
    isOpenClawAutoMemoryEnabled,
    isSelfHealEnabled,
    loadShieldConfig,
    resolveServerCmd,
    resolvePackageRoot,
    loadOpenClawExtract,
  };
}
