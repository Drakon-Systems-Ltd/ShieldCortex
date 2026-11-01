/**
 * Is a symlinked `config.json` authenticated by its signature? (#878 r5)
 *
 * The one verifier the non-src readers use to decide whether a SYMLINKED
 * config.json is honoured or held at the strict fail-closed posture:
 * scripts/pre-tool-hook.mjs (Claude Code hook) and
 * src/setup/openclaw-selfcheck.ts (the synthetic canary) import it from here;
 * hooks/openclaw/cortex-memory/runtime.mjs is copied alone into OpenClaw hook
 * directories and cannot import it, so it carries a byte-identical copy of the
 * region between the BEGIN/END markers below. A test fails on any drift
 * between the two copies, and a parity test drives the same fixtures through
 * src's `checkConfigIntegrity` (src/cloud/config.ts, via inspectConfigIntegrity)
 * and this verifier and requires the same verdict.
 *
 * The rule it serves: src's read layer never adopts (signs) or self-heals
 * through a link, so a linked file is in force only when a signature that
 * already exists AUTHENTICATES its bytes (`valid`, or `self-heal`: the legacy
 * whole-file sig still authenticates the bytes the stale embedded `_sig` no
 * longer matches). Anything else — `tampered`, or `unsigned` (src: unverified)
 * — is held strict. Presence is not a signature: the target of a link can
 * carry any `_sig` string, and an empty, junk or directory `.config-sig` is
 * not one either. Only an HMAC recomputed with the local `.integrity-key`
 * decides.
 *
 * Regular (non-link) files are out of scope here: the hook and the runtime
 * still do not verify them (pre-existing, #509).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

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

/** A sidecar as checkConfigIntegrity reads it: absent → undefined, unreadable → null, else trimmed text. */
function readSidecarSync(file) {
  if (!existsSync(file)) return undefined;
  try {
    return readFileSync(file, "utf-8").trim();
  } catch {
    return null;
  }
}

/** The verdict for `raw` (the bytes `parsed` came from), with the sidecars beside `configPath`. */
export function configSignatureVerdictAt(configPath, parsed, raw) {
  const dir = dirname(configPath);
  const key = readSidecarSync(join(dir, ".integrity-key"));
  return configSignatureVerdict({
    parsed,
    raw,
    key: typeof key === "string" ? key : null,
    legacySig: readSidecarSync(join(dir, ".config-sig")),
  });
}

/**
 * True when `configPath` is a symbolic link whose parsed object no signature
 * authenticates: the reader must hold it at the strict fail-closed posture.
 * False for a regular file, an lstat failure, or a non-object parse (those keep
 * their own handling: a dangling or empty link reads as `{}`, as src reads it).
 */
export function configIsLinkedUnauthenticated(configPath, parsed, raw) {
  try {
    if (!lstatSync(configPath).isSymbolicLink()) return false;
  } catch {
    return false;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  return !verdictAuthenticates(configSignatureVerdictAt(configPath, parsed, raw));
}
