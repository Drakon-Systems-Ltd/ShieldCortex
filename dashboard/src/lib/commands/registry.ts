/**
 * CIC command registry.
 *
 * Each command is a thin, testable adapter: it takes a {@link CommandContext}
 * (bound to the dashboard's real hooks by the CommandRail component) plus the
 * parsed input, performs one operation, and returns console output. The command
 * rail must be REAL — every command here drives an actual API/MCP/router action.
 */
import { parseCommand, type ParsedCommand } from './parse';

export interface RecallHit {
  id: number;
  title: string;
}

export interface ScanSummary {
  target: string;
  riskLevel: string;
  trustScore: number;
  filesScanned: number;
  findingsCount: number;
}

export interface ConsolidateSummary {
  consolidated: number;
  decayed: number;
  deleted: number;
}

export interface RouteRef {
  label: string;
  href: string;
}

/** The live capabilities a command can use, supplied by CommandRail from real hooks. */
export interface CommandContext {
  navigate: (path: string) => void;
  setTheme: (theme: 'terminal' | 'glass') => void;
  recall: (query: string, project?: string) => Promise<RecallHit[]>;
  scan: (target: string, deep: boolean) => Promise<ScanSummary>;
  forget: (id: number) => Promise<void>;
  consolidate: () => Promise<ConsolidateSummary>;
  quarantineList: () => Promise<RecallHit[]>;
  quarantineReview: (id: number, action: 'approve' | 'reject') => Promise<void>;
  ironDome: (action: 'on' | 'off' | 'status') => Promise<string>;
  remember: (text: string) => Promise<{ id: number }>;
  routes: RouteRef[];
}

export interface CommandResult {
  ok: boolean;
  lines: string[];
}

export interface Command {
  name: string;
  usage: string;
  summary: string;
  run: (ctx: CommandContext, parsed: ParsedCommand) => Promise<CommandResult> | CommandResult;
}

const ok = (lines: string[]): CommandResult => ({ ok: true, lines });
const err = (lines: string[]): CommandResult => ({ ok: false, lines });

const go: Command = {
  name: 'go',
  usage: 'go <view>',
  summary: 'navigate to a console view',
  run: (ctx, { args }) => {
    const target = args[0]?.toLowerCase();
    if (!target) return err(['go: which view? ' + ctx.routes.map((r) => r.label).join(' · ')]);
    const match = ctx.routes.find(
      (r) => r.label.toLowerCase().includes(target) || r.href.toLowerCase().includes(target),
    );
    if (!match) {
      return err([`go: unknown view '${target}'. options: ${ctx.routes.map((r) => r.label).join(' · ')}`]);
    }
    ctx.navigate(match.href);
    return ok([`▸ ${match.label}`]);
  },
};

const theme: Command = {
  name: 'theme',
  usage: 'theme <terminal|glass>',
  summary: 'switch the dashboard theme',
  run: (ctx, { args }) => {
    const t = args[0]?.toLowerCase();
    if (t !== 'terminal' && t !== 'glass') return err(["theme: choose 'terminal' or 'glass'"]);
    ctx.setTheme(t);
    return ok([`▸ theme → ${t}`]);
  },
};

const recall: Command = {
  name: 'recall',
  usage: 'recall "<query>" [--project <p>]',
  summary: 'search the memory cortex',
  run: async (ctx, { args, flags }) => {
    const query = args.join(' ').trim();
    if (!query) return err(['recall: give a query, e.g. recall "auth bug"']);
    const project = typeof flags.project === 'string' ? flags.project : undefined;
    const hits = await ctx.recall(query, project);
    if (hits.length === 0) return ok([`recall "${query}" → no memories`]);
    return ok([`recall "${query}" → ${hits.length}`, ...hits.slice(0, 10).map((h) => `  #${h.id} ${h.title}`)]);
  },
};

const scan: Command = {
  name: 'scan',
  usage: 'scan <path> [--deep]',
  summary: 'X-Ray a file, folder, or package',
  run: async (ctx, { args, flags }) => {
    const target = args[0];
    if (!target) return err(['scan: give a path or package']);
    const s = await ctx.scan(target, flags.deep === true);
    return ok([
      `scan ${s.target} → ${s.riskLevel} · trust ${s.trustScore} · ${s.filesScanned} files · ${s.findingsCount} findings`,
    ]);
  },
};

const forget: Command = {
  name: 'forget',
  usage: 'forget <id>',
  summary: 'delete a memory by id',
  run: async (ctx, { args }) => {
    const id = Number(args[0]);
    if (!Number.isInteger(id)) return err(['forget: give a numeric memory id']);
    await ctx.forget(id);
    return ok([`▸ forgot #${id}`]);
  },
};

const consolidate: Command = {
  name: 'consolidate',
  usage: 'consolidate',
  summary: 'run a consolidation pass (STM→LTM, decay, cleanup)',
  run: async (ctx) => {
    const r = await ctx.consolidate();
    return ok([`▸ consolidated ${r.consolidated} · decayed ${r.decayed} · deleted ${r.deleted}`]);
  },
};

const quarantine: Command = {
  name: 'quarantine',
  usage: 'quarantine [approve <id> | reject <id>]',
  summary: 'list pending quarantine, or approve/reject by id',
  run: async (ctx, { args }) => {
    const sub = args[0]?.toLowerCase();
    if (!sub || sub === 'list') {
      const items = await ctx.quarantineList();
      if (items.length === 0) return ok(['quarantine: nothing pending']);
      return ok([`quarantine pending → ${items.length}`, ...items.slice(0, 10).map((h) => `  #${h.id} ${h.title}`)]);
    }
    if (sub === 'approve' || sub === 'reject') {
      const id = Number(args[1]);
      if (!Number.isInteger(id)) return err([`quarantine ${sub}: give a numeric id`]);
      await ctx.quarantineReview(id, sub);
      return ok([`▸ ${sub === 'approve' ? 'approved' : 'rejected'} #${id}`]);
    }
    return err(['quarantine: use list | approve <id> | reject <id>']);
  },
};

const irondome: Command = {
  name: 'irondome',
  usage: 'irondome <on|off|status>',
  summary: 'arm/disarm the Iron Dome, or report its state',
  run: async (ctx, { args }) => {
    const sub = args[0]?.toLowerCase();
    if (sub !== 'on' && sub !== 'off' && sub !== 'status') {
      return err(['irondome: use on | off | status']);
    }
    const line = await ctx.ironDome(sub);
    return ok([line]);
  },
};

const remember: Command = {
  name: 'remember',
  usage: 'remember "<text>"',
  summary: 'store a new memory',
  run: async (ctx, { args }) => {
    const text = args.join(' ').trim();
    if (!text) return err(['remember: give the text to store, e.g. remember "the fix was X"']);
    const m = await ctx.remember(text);
    return ok([`▸ remembered #${m.id}`]);
  },
};

const help: Command = {
  name: 'help',
  usage: 'help',
  summary: 'list commands',
  run: () => ok(['commands:', ...Object.values(COMMANDS).map((c) => `  ${c.usage.padEnd(34)} ${c.summary}`)]),
};

export const COMMANDS: Record<string, Command> = {
  recall,
  scan,
  forget,
  consolidate,
  quarantine,
  irondome,
  remember,
  go,
  theme,
  help,
};

export async function runCommand(input: string, ctx: CommandContext): Promise<CommandResult> {
  const parsed = parseCommand(input);
  if (!parsed) return err([]);
  const cmd = COMMANDS[parsed.name];
  if (!cmd) return err([`unknown command: ${parsed.name} — try 'help'`]);
  try {
    return await cmd.run(ctx, parsed);
  } catch (e) {
    return err([`error: ${e instanceof Error ? e.message : String(e)}`]);
  }
}
