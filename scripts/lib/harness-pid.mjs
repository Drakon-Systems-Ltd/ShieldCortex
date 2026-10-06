import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { basename } from 'node:path';

const validPid = (pid) => Number.isInteger(pid) && pid > 1;

/** Read only process-table ancestry, never an inherited environment hint. */
export function readAncestor(pid) {
  try {
    if (process.platform === 'linux') {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      const end = stat.lastIndexOf(')');
      if (end < 0) return null;
      const ppid = Number(stat.slice(end + 2).split(/\s+/)[1]);
      const argv = readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean);
      return validPid(ppid) && argv.length ? { ppid, argv } : null;
    }
    const line = execFileSync('ps', ['-o', 'ppid=,args=', '-p', String(pid)], { encoding: 'utf8' }).trim();
    const match = line.match(/^(\d+)\s+(.+)$/);
    return match && validPid(Number(match[1])) ? { ppid: Number(match[1]), argv: match[2].split(/\s+/) } : null;
  } catch {
    return null;
  }
}

export function isTransientAncestor(argv) {
  if (!Array.isArray(argv) || argv.length === 0) return false;
  const executable = basename(argv[0]);
  if (['sh', 'dash', 'bash', 'zsh', 'ash'].includes(executable)) {
    return argv.slice(1).some((arg) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg));
  }
  const isNode = /^(?:node|nodejs)(?:\.exe)?$/.test(executable);
  if (!isNode) return false;
  const hook = argv.indexOf('hook');
  return hook > 0 && argv[hook + 1] === 'pre-tool'
    && argv.slice(1, hook).some((arg) => /(?:^|\/)(?:shieldcortex|dist\/index\.js)$/.test(arg));
}

/** Walk from the hook's parent to the first persistent process. */
export function resolveHarnessPid(parentPid = process.ppid, read = readAncestor, maxHops = 8) {
  if (!validPid(parentPid)) return process.pid;
  let pid = parentPid;
  for (let hop = 0; hop < maxHops; hop++) {
    const ancestor = read(pid);
    if (!ancestor) return pid;
    if (!isTransientAncestor(ancestor.argv) || !validPid(ancestor.ppid)) return pid;
    pid = ancestor.ppid;
  }
  return pid;
}
