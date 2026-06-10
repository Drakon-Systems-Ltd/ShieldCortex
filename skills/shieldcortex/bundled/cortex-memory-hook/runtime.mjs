import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

export function createOpenClawRuntime({
  logPrefix = "[shieldcortex]",
  configPath = path.join(homedir(), ".shieldcortex", "config.json"),
} = {}) {
  let shieldConfig = null;
  let shieldConfigMtime = 0;
  let resolvedServerCmd = null;
  let lastCallErrorType = null;

  // mtime-gated cache: re-read on every call if the config file's modified
  // time has advanced. Lets dashboard / CLI toggles take effect on the next
  // event without an OpenClaw gateway restart.
  async function loadShieldConfig() {
    let mtime = 0;
    try {
      const stats = await fs.stat(configPath);
      mtime = stats.mtimeMs;
    } catch {
      mtime = 0;
    }

    if (shieldConfig && mtime === shieldConfigMtime) return shieldConfig;

    try {
      shieldConfig = JSON.parse(await fs.readFile(configPath, "utf-8"));
    } catch {
      shieldConfig = {};
    }
    shieldConfigMtime = mtime;
    return shieldConfig;
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
    loadShieldConfig,
    resolveServerCmd,
    resolvePackageRoot,
    loadOpenClawExtract,
  };
}
