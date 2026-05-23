import { describe, expect, it } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  PRESETS,
  type PresetName,
  instrumentedSign,
  simulateRejectionTrace,
} from './instrumented-sign';

const PRESET_NAMES = Object.keys(PRESETS) as PresetName[];

async function yieldEvery(i: number): Promise<void> {
  if (i % 100 === 0) await new Promise((r) => setTimeout(r, 0));
}

async function meanIterations(preset: PresetName, runs: number): Promise<number> {
  let total = 0;
  for (let i = 0; i < runs; i += 1) {
    const trace = await simulateRejectionTrace({ preset });
    total += trace.acceptedIteration;
    await yieldEvery(i);
  }
  return total / runs;
}

describe('simulation calibration', () => {
  for (const preset of PRESET_NAMES) {
    it(`${preset}: mean iterations ≈ 1 / acceptance (±15%)`, async () => {
      const runs = 800;
      const expected = 1 / PRESETS[preset].acceptance;
      const observed = await meanIterations(preset, runs);
      const ratio = observed / expected;
      expect(ratio).toBeGreaterThan(0.85);
      expect(ratio).toBeLessThan(1.15);
    }, 30000);
  }

  it('rejection-reason mix matches the published proportions (ML-DSA-65)', async () => {
    const counts: Record<string, number> = { z_too_large: 0, r0_too_large: 0, ct0_too_large: 0, hint_too_dense: 0 };
    let total = 0;
    for (let i = 0; i < 800; i += 1) {
      const trace = await simulateRejectionTrace({ preset: 'ML-DSA-65' });
      for (const it of trace.iterations) {
        if (it.rejectionReason) {
          counts[it.rejectionReason] = (counts[it.rejectionReason] ?? 0) + 1;
          total += 1;
        }
      }
      await yieldEvery(i);
    }
    expect(total).toBeGreaterThan(0);
    const target = PRESETS['ML-DSA-65'].rejectionMix;
    expect(Math.abs((counts.z_too_large ?? 0) / total - target.z)).toBeLessThan(0.06);
    expect(Math.abs((counts.r0_too_large ?? 0) / total - target.r0)).toBeLessThan(0.06);
    expect(Math.abs((counts.ct0_too_large ?? 0) / total - target.ct0)).toBeLessThan(0.06);
  }, 30000);
});

describe('instrumentedSign output', () => {
  it('returns a signature that verifies via noble ml_dsa65', async () => {
    const kp = ml_dsa65.keygen();
    const msg = new TextEncoder().encode('verify-test');
    const res = await instrumentedSign(msg, kp.secretKey, undefined, { preset: 'ML-DSA-65' });
    expect(ml_dsa65.verify(res.signature, msg, kp.publicKey)).toBe(true);
    expect(res.acceptedIteration).toBe(res.iterations.length);
    expect(res.iterations.at(-1)?.result).toBe('ACCEPTED');
    for (let i = 0; i < res.iterations.length - 1; i += 1) {
      expect(res.iterations[i]?.result).toBe('REJECTED');
      expect(res.iterations[i]?.rejectionReason).not.toBeNull();
    }
  });
});
