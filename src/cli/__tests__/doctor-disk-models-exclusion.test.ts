import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';

/**
 * Doctor's `Disk` check used to count the entire `~/.shieldcortex/` tree
 * against a 100 MB safety limit. v4.14.3 onwards excludes the `models/`
 * subtree because local AI inference caches (Review Copilot Qwen weights,
 * embedding models) can legitimately reach hundreds of MB for users who
 * opted into local AI — flagging that as runaway memory growth produced
 * a false `Disk: at limit!` and pointed users at irrelevant fixes
 * (`memories prune` / `dedupe` would never touch a model cache).
 */
describe("doctor checkDiskUsage excludes models/ from the 100 MB safety limit", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-disk-check-'));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeBytes(rel: string, bytes: number): void {
    const fullPath = path.join(tmpDir, rel);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, Buffer.alloc(bytes, 0));
  }

  it("returns pass when both data and models are small", async () => {
    writeBytes('memories.db', 1024 * 1024);          // 1 MB DB
    writeBytes('models/embed/file.onnx', 5 * 1024 * 1024); // 5 MB model
    const result = await checkDiskUsage(tmpDir);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/1\.0 MB \/ 100 MB limit \+ 5\.0 MB models/);
  });

  it("does NOT flag a 750 MB models cache when data is small (the bug)", async () => {
    writeBytes('memories.db', 2 * 1024 * 1024);          // 2 MB DB
    writeBytes('models/review-copilot/Qwen2.5-0.5B/model_q4.onnx', 200 * 1024 * 1024); // 200 MB
    const result = await checkDiskUsage(tmpDir);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/2\.0 MB \/ 100 MB limit \+ 200\.0 MB models/);
  });

  it("flags fail when the data portion exceeds the limit, regardless of models size", async () => {
    writeBytes('memories.db', 99 * 1024 * 1024);              // 99 MB DB
    writeBytes('audit/realtime.jsonl', 5 * 1024 * 1024);      // 5 MB audit
    writeBytes('models/embed/file.onnx', 1 * 1024 * 1024);    // 1 MB model
    const result = await checkDiskUsage(tmpDir);
    expect(result.status).toBe('fail');
    expect(result.message).toContain('at limit');
    // Fix should be DB-trimming commands, not model-cache deletion
    expect(result.fix).toMatch(/memories prune|memories dedupe/);
  });

  it("flags warn at 80% of the data limit", async () => {
    writeBytes('memories.db', 85 * 1024 * 1024);              // 85 MB
    writeBytes('models/embed/file.onnx', 500 * 1024 * 1024);  // 500 MB (ignored)
    const result = await checkDiskUsage(tmpDir);
    expect(result.status).toBe('warn');
    expect(result.message).toContain('approaching limit');
  });

  it("omits the models suffix when no models/ subtree is present", async () => {
    writeBytes('memories.db', 1024 * 1024);
    const result = await checkDiskUsage(tmpDir);
    expect(result.status).toBe('pass');
    expect(result.message).not.toContain('models');
  });

  it("returns the directory-not-yet-created pass when scDir does not exist", async () => {
    const missing = path.join(tmpDir, 'never-created');
    const result = await checkDiskUsage(missing);
    expect(result.status).toBe('pass');
    expect(result.message).toContain('directory not yet created');
  });
});
