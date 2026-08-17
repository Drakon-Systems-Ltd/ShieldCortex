/**
 * #342 interpreter recursive-delete floor.
 * evaluateToolCall only. No process. No filesystem touch.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

function bash(command: string) {
  return evaluateToolCall('Bash', { command });
}

const R = String.fromCharCode(114);
const M = String.fromCharCode(109);

function shellVerb(): string {
  return R + M + ' -' + R + 'f';
}

function pyTreeRoot(): string {
  return 'python3 -c "import shutil; shutil.' + R + M + 'tree(\'/\')"';
}

function pyTreeIgnore(): string {
  return 'python3 -c "import shutil; shutil.' + R + M + 'tree(\'/var/tmp/x\', ignore_errors=True)"';
}

function nodeSyncRoot(): string {
  return 'node -e "require(\'fs\').' + R + M + 'Sync(\'/\',{recursive:true,force:true})"';
}

function nodeHome(): string {
  return 'node -e "require(\'fs\').promises.' + R + M + '(\'/home/u\',{recursive:true})"';
}

function rubyForce(): string {
  return 'ruby -e "require \'fileutils\'; FileUtils.' + R + M + '_rf(\'/\')"';
}

function nodeOneFile(): string {
  return 'node -e "require(\'fs\').' + R + M + 'Sync(\'/tmp/one-file.txt\')"';
}

describe('#342 interpreter recursive delete is catastrophic', () => {
  it('python shutil tree root blocks', () => {
    const v = bash(pyTreeRoot());
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.signals).toContain('recursive-force-delete');
  });
  it('python shutil tree ignore_errors blocks', () => {
    const v = bash(pyTreeIgnore());
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
  });
  it('node fs sync root recursive blocks', () => {
    const v = bash(nodeSyncRoot());
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.signals).toContain('recursive-force-delete');
  });
  it('node fs.promises home recursive blocks', () => {
    const v = bash(nodeHome());
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
  });
  it('FileUtils force root blocks', () => {
    const v = bash(rubyForce());
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
  });
});

describe('#342 mention / precision holdouts', () => {
  it('pattern-string dict inside python -c is still a mention', () => {
    const verb = shellVerb();
    const v = bash('python3 -c "PATTERNS = [\'' + verb + ' /tmp/x\']"');
    expect(v.signals ?? []).not.toContain('recursive-force-delete');
    expect(v.decision).not.toBe('block');
  });
  it('single-file node sync without recursive is not catastrophic', () => {
    const v = bash(nodeOneFile());
    expect(v.signals ?? []).not.toContain('recursive-force-delete');
  });
  it('shell recursive delete of root still blocks', () => {
    const v = bash(shellVerb() + ' /');
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('recursive-force-delete');
  });
});

