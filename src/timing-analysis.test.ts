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
