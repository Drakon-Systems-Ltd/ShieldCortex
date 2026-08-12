import { describe, it, expect } from '@jest/globals';
import { validateOpenClawConfig, VALIDATE_ARGV } from '../integrations/openclaw-config-validate.js';
import type { SpawnOutcome, ValidateDeps } from '../integrations/openclaw-config-validate.js';

/**
 * #221 — the verdict is three-state, and every ambiguous case must land on
 * `indeterminate`.
 *
 * Suppressing a remedy is destructive: if this module says "invalid" when it
 * should not, doctor hides the advice that would have fixed the host. So the
 * false-red cases below matter more than the happy path, and each was measured
 * against the real binary before being written down.
 */

const HOME = '/home/tester';

function deps(over: Partial<ValidateDeps> = {}): ValidateDeps {
  return {
    exists: () => true,
    configPath: () => '/home/tester/.openclaw/openclaw.json',
    resolveBin: () => '/opt/homebrew/bin/openclaw',
    ...over,
  };
}

function outcome(over: Partial<SpawnOutcome> = {}): SpawnOutcome {
  return { status: 0, stdout: '', stderr: '', ...over };
}

describe('#221 — a valid config, including one with warnings', () => {
  it('exit 0 is valid', () => {
    const v = validateOpenClawConfig(HOME, deps({ run: () => outcome({ status: 0 }) }));
    expect(v.state).toBe('valid');
  });

  /**
   * THE FALSE-RED THIS PRODUCT WOULD HAVE SHIPPED.
   *
   * The dev box prints "1 warning(s): ! plugins.entries.ekho-adapter:
   * duplicate plugin id detected" and still exits 0 — and the operator in the
   * field report ALSO had an ekho-adapter problem, so the two states are easy
   * to conflate. Anything that reads the output to reach a verdict fails here.
   */
  it('warnings on stdout with exit 0 are STILL valid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({
        status: 0,
        stdout: 'Config valid: ~/.openclaw/openclaw.json\n1 warning(s):\n  ! plugins.entries.ekho-adapter: duplicate plugin id detected',
      }),
    }));
    expect(v.state).toBe('valid');
  });
});

describe('#221 — genuinely invalid', () => {
  it('non-zero exit is invalid, and quotes what OpenClaw said', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({
        status: 1,
        stdout: '',
        stderr: 'OpenClaw config is invalid: /home/tester/.openclaw/openclaw.json\n  × plugins.load.paths: plugin path not found: /nope\n\nRun `openclaw doctor --fix` to repair.',
      }),
    }));

    expect(v.state).toBe('invalid');
    if (v.state !== 'invalid') throw new Error('unreachable');
    expect(v.detail.join('\n')).toContain('plugin path not found');
  });

  it('never yields an empty detail', () => {
    // The marker is present, so this IS invalid — but summarising could still
    // come back empty, and a suppression with no stated cause is unarguable.
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: 1, stderr: 'config is invalid' }),
    }));

    expect(v.state).toBe('invalid');
    if (v.state !== 'invalid') throw new Error('unreachable');
    expect(v.detail.length).toBeGreaterThan(0);
  });

  it('exit 1 with NO output at all is indeterminate, not invalid', () => {
    // Nothing said the config is bad. Silence is not evidence, and the cost of
    // guessing wrong here is stripping every remedy from a healthy host.
    const v = validateOpenClawConfig(HOME, deps({ run: () => outcome({ status: 1 }) }));
    expect(v.state).toBe('indeterminate');
  });
});

describe('#221 — a non-zero exit is not proof of an invalid config', () => {
  /**
   * THE INVERTED-#221 CASE, and the worst thing this module could do.
   *
   * An OpenClaw predating `config validate` answers an unknown subcommand with
   * exit 1. Measured on 2026.7.1-2: `openclaw config <unknown>` exits 1 with
   * "Too many arguments for this command." If that reads as "config invalid",
   * a HEALTHY host gets a red config row AND has every remedy stripped —
   * including the one on the check whose message says the gateway is running
   * with no memory firewall and no action guard.
   */
  it('an OpenClaw that does not know the subcommand is indeterminate', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({
        status: 1,
        stdout: '',
        stderr: 'Too many arguments for this command.\nTry: openclaw config validate --help',
      }),
    }));

    expect(v.state).toBe('indeterminate');
    if (v.state !== 'indeterminate') throw new Error('unreachable');
    expect(v.reason).toContain('not supported');
  });

  it('an OpenClaw that does not know the command at all is indeterminate', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({
        status: 1,
        stderr: '[openclaw] Could not start the CLI.\n[openclaw] Reason: Unknown command: openclaw config validate.',
      }),
    }));
    expect(v.state).toBe('indeterminate');
  });

  it('but a JSON invalid body IS invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: 1, stdout: '{"valid":false,"path":"/x","issues":[{"path":"a","message":"b"}]}' }),
    }));
    expect(v.state).toBe('invalid');
  });

  it('and a bullet-marked issue IS invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: 1, stderr: '  × plugins.load.paths: plugin path not found: /nope' }),
    }));
    expect(v.state).toBe('invalid');
  });
});

describe('#221 — the argv must never grow a flag', () => {
  it('is exactly `config validate`', () => {
    // `--json` is tidier and was deliberately rejected: an OpenClaw that does
    // not know the flag exits non-zero with a usage dump, manufacturing the
    // false red this module exists to avoid.
    expect([...VALIDATE_ARGV]).toEqual(['config', 'validate']);
    expect(VALIDATE_ARGV.some(a => a.startsWith('-'))).toBe(false);
  });
});

describe('#221 — every uncertainty is indeterminate, never invalid', () => {
  it('no OpenClaw config on this host — does not even spawn', () => {
    let spawned = false;
    const v = validateOpenClawConfig(HOME, deps({
      exists: () => false,
      run: () => { spawned = true; return outcome({ status: 1 }); },
    }));

    expect(v.state).toBe('indeterminate');
    // The measured trap: `config validate` on a missing file exits 1 with
    // {"valid":false,"error":"file not found"} — a pure exit-code gate would
    // call an OpenClaw-less host "config invalid".
    expect(spawned).toBe(false);
  });

  it('openclaw binary not installed', () => {
    const v = validateOpenClawConfig(HOME, deps({ resolveBin: () => null }));
    expect(v.state).toBe('indeterminate');
  });

  /**
   * spawnSync reports an absent binary as status:null + error.code ENOENT, NOT
   * as 127 (127 is the shell path only). The `status ?? 1` idiom used elsewhere
   * in the codebase collapses this into "exit 1" — which would be read as a
   * broken config on a host that has nothing to fix.
   */
  it('binary vanishing between resolve and spawn is NOT invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: null, error: Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }) }),
    }));
    expect(v.state).toBe('indeterminate');
  });

  it('a timeout is NOT invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: null, error: Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }) }),
    }));
    expect(v.state).toBe('indeterminate');
  });

  it('a kill signal is NOT invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => outcome({ status: null, signal: 'SIGTERM' }),
    }));
    expect(v.state).toBe('indeterminate');
  });

  it('a throwing spawn is NOT invalid', () => {
    const v = validateOpenClawConfig(HOME, deps({
      run: () => { throw new Error('EACCES: permission denied'); },
    }));
    expect(v.state).toBe('indeterminate');
    if (v.state !== 'indeterminate') throw new Error('unreachable');
    expect(v.reason).toContain('EACCES');
  });

  it('never spawns a real subprocess from the test runner', () => {
    // No `run` injected: the JEST_WORKER_ID guard must catch it. If this ever
    // regresses, the suite starts shelling out to the developer's real binary.
    expect(process.env.JEST_WORKER_ID).toBeDefined();
    const v = validateOpenClawConfig(HOME, deps({ run: undefined }));
    expect(v.state).toBe('indeterminate');
    if (v.state !== 'indeterminate') throw new Error('unreachable');
    expect(v.reason).toContain('test runner');
  });
});
