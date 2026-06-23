import { describe, expect, it } from 'vitest';
import {
  binValues,
  empiricalCdf,
  geometricCdf,
  geometricMean,
  geometricPmf,
  histogramBuckets,
  ksMaxGap,
  mean,
  quantile,
} from './distributions';

describe('geometricPmf', () => {
  it('puts mass p on k=1', () => {
    expect(geometricPmf(0.25, 1)).toBeCloseTo(0.25, 12);
  });

  it('decays by a factor of (1-p) each step', () => {
    const p = 0.3;
    expect(geometricPmf(p, 2) / geometricPmf(p, 1)).toBeCloseTo(1 - p, 12);
    expect(geometricPmf(p, 3) / geometricPmf(p, 2)).toBeCloseTo(1 - p, 12);
  });

  it('sums to ~1 over a long tail', () => {
    const p = 0.26;
    let total = 0;
    for (let k = 1; k <= 500; k += 1) total += geometricPmf(p, k);
    expect(total).toBeCloseTo(1, 6);
  });

  it('returns 0 for out-of-range inputs', () => {
    expect(geometricPmf(0, 1)).toBe(0);
    expect(geometricPmf(1.2, 1)).toBe(0);
    expect(geometricPmf(0.3, 0)).toBe(0);
  });
});

describe('geometricCdf', () => {
  it('matches the cumulative sum of the PMF', () => {
    const p = 0.4;
    let cumulative = 0;
    for (let k = 1; k <= 10; k += 1) {
      cumulative += geometricPmf(p, k);
      expect(geometricCdf(p, k)).toBeCloseTo(cumulative, 12);
    }
  });

  it('approaches 1 in the tail', () => {
    expect(geometricCdf(0.5, 40)).toBeCloseTo(1, 9);
  });
});

describe('geometricMean', () => {
  it('is 1 / p', () => {
    expect(geometricMean(0.25)).toBeCloseTo(4, 12);
    expect(geometricMean(0.5)).toBeCloseTo(2, 12);
  });
});

describe('histogramBuckets', () => {
  it('produces a dense [1..max] range including empty middle buckets', () => {
    const buckets = histogramBuckets([1, 1, 3]);
    expect(buckets.map((b) => b.iteration)).toEqual([1, 2, 3]);
    expect(buckets[1]?.count).toBe(0);
  });

  it('proportions sum to 1', () => {
    const buckets = histogramBuckets([1, 2, 2, 3, 5, 5, 5]);
    const sum = buckets.reduce((a, b) => a + b.proportion, 0);
    expect(sum).toBeCloseTo(1, 12);
  });

  it('returns an empty array for no observations', () => {
    expect(histogramBuckets([])).toEqual([]);
  });
});

describe('empiricalCdf', () => {
  it('is monotonic and ends at 1', () => {
    const points = empiricalCdf([3, 1, 2, 2, 5]);
    expect(points.at(0)?.x).toBe(1);
    expect(points.at(-1)?.p).toBeCloseTo(1, 12);
    for (let i = 1; i < points.length; i += 1) {
      expect(points[i]!.p).toBeGreaterThanOrEqual(points[i - 1]!.p);
      expect(points[i]!.x).toBeGreaterThan(points[i - 1]!.x);
    }
  });

  it('collapses duplicate values to a single cumulative step', () => {
    const points = empiricalCdf([2, 2, 2, 2]);
    expect(points).toHaveLength(1);
    expect(points[0]).toEqual({ x: 2, p: 1 });
  });
});

describe('ksMaxGap', () => {
  it('is 0 for identical samples', () => {
    const s = [1, 2, 3, 4, 5];
    expect(ksMaxGap(s, s).statistic).toBe(0);
  });

  it('is 1 for fully separated samples, located at the lower group', () => {
    const a = Array.from({ length: 50 }, () => 1);
    const b = Array.from({ length: 50 }, () => 9);
    const gap = ksMaxGap(a, b);
    expect(gap.statistic).toBe(1);
    expect(gap.x).toBe(1);
  });

  it('handles empty input', () => {
    expect(ksMaxGap([], [1, 2, 3])).toEqual({ statistic: 0, x: 0 });
  });
});

describe('mean', () => {
  it('averages a sample', () => {
    expect(mean([2, 4, 6])).toBeCloseTo(4, 12);
  });

  it('is 0 for an empty sample', () => {
    expect(mean([])).toBe(0);
  });
});

describe('quantile', () => {
  it('returns the median for q=0.5', () => {
    expect(quantile([1, 2, 3, 4, 5], 0.5)).toBe(3);
  });

  it('interpolates between points', () => {
    expect(quantile([0, 10], 0.25)).toBeCloseTo(2.5, 12);
  });

  it('clamps out-of-range q', () => {
    expect(quantile([1, 2, 3], -1)).toBe(1);
    expect(quantile([1, 2, 3], 2)).toBe(3);
  });
});

describe('binValues', () => {
  it('distributes values across equal-width bins, proportions summing to 1', () => {
    const bins = binValues([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 5);
    expect(bins).toHaveLength(5);
    expect(bins.reduce((a, b) => a + b.count, 0)).toBe(10);
    expect(bins.reduce((a, b) => a + b.proportion, 0)).toBeCloseTo(1, 12);
  });

  it('puts the maximum value in the last bin', () => {
    const bins = binValues([1, 2, 3, 4, 100], 4);
    expect(bins.at(-1)?.count).toBe(1);
  });

  it('collapses a degenerate (all-equal) sample to a single bin', () => {
    expect(binValues([5, 5, 5], 8)).toEqual([{ start: 5, end: 5, count: 3, proportion: 1 }]);
  });

  it('returns empty for no values', () => {
    expect(binValues([], 5)).toEqual([]);
  });
});
