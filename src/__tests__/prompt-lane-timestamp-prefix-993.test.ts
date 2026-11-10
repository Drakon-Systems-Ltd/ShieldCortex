import { beforeAll, describe, expect, it } from '@jest/globals';
import path from 'path';
import { fileURLToPath } from 'url';

// #993 review (TARS, 34ebba98): LEADING_TIMESTAMP_PREFIX used `[^\]]*`, which
// crosses line breaks. A prompt such as
//   "[Tue 2026-11-03 11:48 UTC\nAutomated liveness check\n] x"
// lost its line-anchored lane marker in the lane text, so automation, cron and
// subagent turns fell to the interactive lane. The lane text must never select
// a wider lane than the raw prompt did before the timestamp strip existed.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB = path.resolve(__dirname, '..', '..', 'scripts', 'lib');

let laneText: (s: string) => string;
let detectLane: (a: { text: string; env?: Record<string, string> }) => { lane: string };

beforeAll(async () => {
  laneText = (await import(new URL(`file://${path.join(LIB, 'prompt-sanitiser.mjs')}`).href)).sanitisePromptForLaneDetection;
  detectLane = (await import(new URL(`file://${path.join(LIB, 'recall-lane.mjs')}`).href)).detectLane;
});

const MARKERS: Array<[string, string]> = [
  ['automation', 'Automated liveness check from a watchdog timer.'],
  ['cron', '[cron:abc123 nightly-job] run the sweep'],
  ['cron', 'A scheduled reminder has been triggered. The reminder content is:'],
  ['subagent', '[Subagent Task] summarise the file'],
];
const BREAKS = ['\n', '\r\n', '\r', ' ', ' '];

const oldLane = (p: string) => detectLane({ text: p, env: {} }).lane;
const newLane = (p: string) => detectLane({ text: laneText(p), env: {} }).lane;

describe('lane text keeps markers inside a bracket that spans lines (#993)', () => {
  for (const [lane, marker] of MARKERS) {
    for (const br of BREAKS) {
      it(`${lane} marker after a ${JSON.stringify(br)}-split timestamp bracket`, () => {
        const prompt = `[Tue 2026-11-03 11:48 UTC${br}${marker}${br}] x`;
        expect(oldLane(prompt)).toBe(lane);
        expect(newLane(prompt)).toBe(lane);
      });
    }

    it(`${lane} marker after a normal single-line timestamp is still found`, () => {
      const prompt = `[Tue 2026-11-03 11:48 UTC] ${marker}`;
      expect(newLane(prompt)).toBe(lane);
    });
  }

  it('a multi-line bracket is not stripped at all', () => {
    const prompt = '[Tue 2026-11-03 11:48 UTC\nhello\n] x';
    expect(laneText(prompt)).toBe(prompt);
  });

  it('the single-line envelope timestamp is still stripped', () => {
    expect(laneText('[Tue 2026-11-03 11:48 UTC] hello')).toBe('hello');
  });

  it('new lane equals old lane when the marker follows a timestamp line', () => {
    for (const [, marker] of MARKERS) {
      for (const br of BREAKS) {
        for (const p of [`[Mon 2026-11-09 23:40 UTC${br}${marker}] tail`, `[Mon 2026-11-09 23:40 UTC] x${br}${marker}`]) {
          expect(newLane(p)).toBe(oldLane(p));
        }
      }
    }
  });
});
