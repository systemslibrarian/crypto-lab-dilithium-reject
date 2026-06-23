/**
 * Pure statistical helpers for the rejection-sampling visualizations.
 *
 * No DOM and no randomness live here — every function is deterministic and
 * unit-tested in `distributions.test.ts`. The SVG charts in `main.ts` are thin
 * renderers over the shapes produced here.
 *
 * The pedagogical anchor: ML-DSA signing accepts a candidate on each iteration
 * with a fixed probability `p`, independently. The number of iterations until
 * the first acceptance is therefore a *geometric* random variable, so the
 * observed histogram should track the geometric PMF and the mean should sit at
 * `1 / p`. These helpers make that claim visible and checkable.
 */

/** Geometric PMF on {1, 2, 3, ...}: P(first success on trial k) = (1-p)^(k-1) * p. */
export function geometricPmf(p: number, k: number): number {
  if (!(p > 0 && p <= 1) || k < 1 || !Number.isFinite(k)) return 0;
  return (1 - p) ** (k - 1) * p;
}

/** Geometric CDF: P(X <= k) = 1 - (1-p)^floor(k). */
export function geometricCdf(p: number, k: number): number {
  if (!(p > 0 && p <= 1) || k < 1) return 0;
  return 1 - (1 - p) ** Math.floor(k);
}

/** Mean of a geometric distribution: 1 / p. */
export function geometricMean(p: number): number {
  return p > 0 ? 1 / p : 0;
}

export interface HistogramBucket {
  /** Iteration count k (1-based). */
  iteration: number;
  count: number;
  /** count / total observations. */
  proportion: number;
}

/**
 * Bucket observed iteration counts into a dense [1..max] array, so empty
 * buckets in the middle still render as gaps rather than being skipped.
 */
export function histogramBuckets(values: number[]): HistogramBucket[] {
  if (values.length === 0) return [];
  const counts = new Map<number, number>();
  let max = 1;
  for (const v of values) {
    counts.set(v, (counts.get(v) ?? 0) + 1);
    if (v > max) max = v;
  }
  const out: HistogramBucket[] = [];
  for (let k = 1; k <= max; k += 1) {
    const count = counts.get(k) ?? 0;
    out.push({ iteration: k, count, proportion: count / values.length });
  }
  return out;
}

export interface CdfPoint {
  x: number;
  /** Empirical P(X <= x). */
  p: number;
}

/**
 * Empirical CDF as a set of step points (one per distinct value), each carrying
 * the cumulative proportion at that value. Used to overlay two populations in
 * the KS-test chart so the reader can see them coincide.
 */
export function empiricalCdf(values: number[]): CdfPoint[] {
  if (values.length === 0) return [];
  const sorted = [...values].sort((a, b) => a - b);
  const points: CdfPoint[] = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const x = sorted[i] ?? 0;
    const p = (i + 1) / sorted.length;
    const last = points.at(-1);
    if (last && last.x === x) {
      last.p = p;
    } else {
      points.push({ x, p });
    }
  }
  return points;
}

/** Mean of a sample (0 for an empty sample). */
export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

/** Linear-interpolated quantile of a sample (q in [0,1]). */
export function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * Math.min(1, Math.max(0, q));
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const low = sorted[lo] ?? 0;
  if (lo === hi) return low;
  const high = sorted[hi] ?? 0;
  return low + (high - low) * (pos - lo);
}

export interface Bin {
  start: number;
  end: number;
  count: number;
  proportion: number;
}

/**
 * Bin continuous values (e.g. measured signing times in ms) into `binCount`
 * equal-width buckets spanning [min, max]. Used by the real-timing histogram.
 */
export function binValues(values: number[], binCount: number): Bin[] {
  if (values.length === 0 || binCount < 1) return [];
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (const v of values) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  if (min === max) {
    return [{ start: min, end: max, count: values.length, proportion: 1 }];
  }
  const width = (max - min) / binCount;
  const bins: Bin[] = Array.from({ length: binCount }, (_v, i) => ({
    start: min + i * width,
    end: min + (i + 1) * width,
    count: 0,
    proportion: 0,
  }));
  for (const v of values) {
    let idx = Math.floor((v - min) / width);
    if (idx >= binCount) idx = binCount - 1;
    if (idx < 0) idx = 0;
    bins[idx]!.count += 1;
  }
  for (const b of bins) b.proportion = b.count / values.length;
  return bins;
}

export interface KsGap {
  /** The two-sample KS statistic: the largest vertical gap between the ECDFs. */
  statistic: number;
  /** The x value at which that largest gap occurs (0 if either sample is empty). */
  x: number;
}

/**
 * Two-sample Kolmogorov–Smirnov statistic together with the location of the
 * maximal gap, computed by a single merge-walk over both sorted samples. The
 * `statistic` alone is what `distinguishabilityTest` reports; the `x` lets the
 * chart draw the gap where it actually occurs.
 */
export function ksMaxGap(a: number[], b: number[]): KsGap {
  if (a.length === 0 || b.length === 0) return { statistic: 0, x: 0 };
  const as = [...a].sort((x, y) => x - y);
  const bs = [...b].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let d = 0;
  let xAt = as[0] ?? 0;

  while (i < as.length && j < bs.length) {
    const x = Math.min(as[i] ?? Number.POSITIVE_INFINITY, bs[j] ?? Number.POSITIVE_INFINITY);
    while (i < as.length && (as[i] ?? Number.POSITIVE_INFINITY) <= x) i += 1;
    while (j < bs.length && (bs[j] ?? Number.POSITIVE_INFINITY) <= x) j += 1;
    const gap = Math.abs(i / as.length - j / bs.length);
    if (gap > d) {
      d = gap;
      xAt = x;
    }
  }

  return { statistic: d, x: xAt };
}
