import { describe, expect, it } from 'vitest';
import { distinguishabilityTest, type TimingObservation } from './timing-analysis';

function obs(iterations: number[]): TimingObservation[] {
  return iterations.map((iter, i) => ({
    signatureIndex: i,
    observedTimeMs: iter * 0.5,
    inferredIterations: iter,
  }));
}

describe('distinguishabilityTest', () => {
  it('returns ksStatistic=0 for identical populations', () => {
    const a = obs([1, 2, 3, 4, 5, 1, 2, 3, 4, 5]);
    const b = obs([1, 2, 3, 4, 5, 1, 2, 3, 4, 5]);
    const v = distinguishabilityTest(a, b);
    expect(v.ksStatistic).toBe(0);
    expect(v.exceedsCritical).toBe(false);
    expect(v.alpha).toBe(0.05);
    expect(v.criticalValue).toBeGreaterThan(0);
    expect(v.note).toMatch(/No evidence/);
  });

  it('flags clearly distinct distributions as exceeding the threshold', () => {
    const small = obs(Array.from({ length: 200 }, () => 1));
    const big = obs(Array.from({ length: 200 }, () => 20));
    const v = distinguishabilityTest(small, big);
    expect(v.ksStatistic).toBe(1);
    expect(v.exceedsCritical).toBe(true);
    expect(v.note).toMatch(/exceeds/);
  });

  it('handles empty input gracefully', () => {
    const v = distinguishabilityTest([], obs([1, 2, 3]));
    expect(v.ksStatistic).toBe(0);
    expect(v.exceedsCritical).toBe(false);
    expect(v.note).toMatch(/Insufficient/);
  });

  it('critical value shrinks as sample size grows (more power)', () => {
    const a100 = obs(Array.from({ length: 100 }, (_, i) => i % 5));
    const a1000 = obs(Array.from({ length: 1000 }, (_, i) => i % 5));
    const v100 = distinguishabilityTest(a100, a100);
    const v1000 = distinguishabilityTest(a1000, a1000);
    expect(v1000.criticalValue).toBeLessThan(v100.criticalValue);
  });
});

describe('leaky-signer positive control (Exhibit 6 broken scenario)', () => {
  const geometricDraw = (p: number): number => {
    let k = 1;
    while (Math.random() >= p) k += 1;
    return k;
  };
  const population = (p: number, n: number): TimingObservation[] =>
    obs(Array.from({ length: n }, () => geometricDraw(p)));

  it('detects the demo leak parameters (p=0.196 vs p=0.136) at N=1500', () => {
    // Same acceptance gap the leaky scenario injects (LEAK_DELTA = 0.06 off
    // the ML-DSA-65 reference p). Theoretical KS distance ≈ 0.14 vs a critical
    // value ≈ 0.05 at this N, so a miss here would mean the positive control
    // is broken, not bad luck.
    const v = distinguishabilityTest(population(0.196, 1500), population(0.136, 1500));
    expect(v.exceedsCritical).toBe(true);
  });

  it('stays quiet for two faithful populations at the same p', () => {
    // One draw can still cross by chance (~alpha), so take the best of three —
    // P(all three cross) ≈ alpha³, negligible flake risk.
    const results = Array.from({ length: 3 }, () =>
      distinguishabilityTest(population(0.196, 1000), population(0.196, 1000)),
    );
    expect(results.some((v) => !v.exceedsCritical)).toBe(true);
  });
});
