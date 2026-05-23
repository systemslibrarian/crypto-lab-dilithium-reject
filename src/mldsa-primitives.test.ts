import { describe, expect, it } from 'vitest';
import {
  ML_DSA_65,
  expandMask,
  hintWeight,
  highBits,
  infinityNorm,
  lowBits,
  randomBytes,
  sampleInBall,
} from './mldsa-primitives';

describe('infinityNorm', () => {
  it('uses centered representation: q-1 maps to 1', () => {
    const p = new Int32Array([ML_DSA_65.q - 1]);
    expect(infinityNorm(p, ML_DSA_65.q)).toBe(1);
  });

  it('finds the maximum centered magnitude', () => {
    const p = new Int32Array([0, 3, -4, 2]);
    expect(infinityNorm(p, ML_DSA_65.q)).toBe(4);
  });

  it('returns 0 for an all-zero polynomial', () => {
    expect(infinityNorm(new Int32Array(8), ML_DSA_65.q)).toBe(0);
  });
});

describe('highBits / lowBits', () => {
  it('round-trips: r === highBits(r, a) * a + lowBits(r, a) for a sweep', () => {
    const alpha = 2 * ML_DSA_65.gamma2;
    for (let r = -alpha; r <= alpha; r += Math.floor(alpha / 13)) {
      expect(highBits(r, alpha) * alpha + lowBits(r, alpha)).toBe(r);
    }
  });
});

describe('sampleInBall', () => {
  it('produces exactly tau nonzero coefficients in {-1, +1}', () => {
    const c = sampleInBall(randomBytes(32), ML_DSA_65.tau, ML_DSA_65.n);
    expect(c).toHaveLength(ML_DSA_65.n);
    let nonzero = 0;
    for (let i = 0; i < c.length; i += 1) {
      const v = c[i] ?? 0;
      if (v !== 0) {
        expect(v === 1 || v === -1).toBe(true);
        nonzero += 1;
      }
    }
    expect(nonzero).toBe(ML_DSA_65.tau);
  });

  it('is deterministic in the seed', () => {
    const seed = randomBytes(32);
    const a = sampleInBall(seed, ML_DSA_65.tau, ML_DSA_65.n);
    const b = sampleInBall(seed, ML_DSA_65.tau, ML_DSA_65.n);
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});

describe('expandMask', () => {
  it('produces n coefficients in (-gamma1, gamma1]', () => {
    const y = expandMask(randomBytes(64), 0, ML_DSA_65.gamma1, ML_DSA_65.n);
    expect(y).toHaveLength(ML_DSA_65.n);
    for (let i = 0; i < y.length; i += 1) {
      const v = y[i] ?? 0;
      expect(v).toBeGreaterThan(-ML_DSA_65.gamma1);
      expect(v).toBeLessThanOrEqual(ML_DSA_65.gamma1);
    }
  });

  it('respects different gamma1 values for different presets', () => {
    const small = expandMask(randomBytes(64), 0, 131072, ML_DSA_65.n);
    for (let i = 0; i < small.length; i += 1) {
      const v = small[i] ?? 0;
      expect(Math.abs(v)).toBeLessThanOrEqual(131072);
    }
  });
});

describe('hintWeight', () => {
  it('counts nonzero positions across polynomials', () => {
    const a = new Int32Array([1, 0, 1, 0, 1]);
    const b = new Int32Array([0, 1, 0, 0]);
    expect(hintWeight([a, b])).toBe(4);
  });

  it('returns 0 for empty input', () => {
    expect(hintWeight([])).toBe(0);
  });
});
