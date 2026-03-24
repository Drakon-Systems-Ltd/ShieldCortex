import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

export function createOpenClawRuntime({ logPrefix = "[shieldcortex]" } = {}) {
  let shieldConfig = null;
  let resolvedServerCmd = null;
  let lastCallErrorType = null;

  async function loadShieldConfig() {
    if (shieldConfig) return shieldConfig;

    try {
      const configPath = path.join(homedir(), ".shieldcortex", "config.json");
      shieldConfig = JSON.parse(await fs.readFile(configPath, "utf-8"));
    } catch {
      shieldConfig = {};
    }

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

  async function callCortex(tool, args = {}, options = { retries: 0, timeout: 15000 }) {
    const serverCmd = await resolveServerCmd();

    return new Promise((resolve) => {
      const cmdArgs = ["mcporter", "call", "--stdio", serverCmd, tool];
      for (const [key, value] of Object.entries(args)) {
        cmdArgs.push(`${key}:${String(value).replace(/'/g, "''")}`);
      }

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
  };
}
