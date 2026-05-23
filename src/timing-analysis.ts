import { simulateRejectionTrace, type PresetName } from './instrumented-sign';
import { uniform01 } from './mldsa-primitives';

export interface TimingObservation {
  signatureIndex: number;
  observedTimeMs: number;
  inferredIterations: number;
}

function ksStatistic(a: number[], b: number[]): number {
  const as = [...a].sort((x, y) => x - y);
  const bs = [...b].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let d = 0;

  while (i < as.length && j < bs.length) {
    const x = Math.min(as[i] ?? Number.POSITIVE_INFINITY, bs[j] ?? Number.POSITIVE_INFINITY);
    while (i < as.length && (as[i] ?? Number.POSITIVE_INFINITY) <= x) i += 1;
    while (j < bs.length && (bs[j] ?? Number.POSITIVE_INFINITY) <= x) j += 1;
    const fa = i / as.length;
    const fb = j / bs.length;
    d = Math.max(d, Math.abs(fa - fb));
  }

  return d;
}

function ksCriticalValue(n1: number, n2: number, alpha = 0.05): number {
  const cAlpha = alpha === 0.05 ? 1.36 : 1.63;
  return cAlpha * Math.sqrt((n1 + n2) / (n1 * n2));
}

export async function collectTimingObservations(
  numSignatures: number,
  options: { preset?: PresetName; onProgress?: (done: number) => void } = {},
): Promise<TimingObservation[]> {
  const observations: TimingObservation[] = [];
  const chunkSize = 50;
  for (let i = 0; i < numSignatures; i += 1) {
    const trace = await simulateRejectionTrace({ preset: options.preset });
    const noise = (uniform01() - 0.5) * 0.06;
    const observedTimeMs = Math.max(0, trace.totalTimeMs + noise);

    observations.push({
      signatureIndex: i,
      observedTimeMs,
      inferredIterations: trace.acceptedIteration,
    });

    if (options.onProgress && (i + 1) % chunkSize === 0) {
      options.onProgress(i + 1);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  options.onProgress?.(numSignatures);
  return observations;
}

export function distinguishabilityTest(
  sk1Observations: TimingObservation[],
  sk2Observations: TimingObservation[],
): {
  exceedsCritical: boolean;
  ksStatistic: number;
  criticalValue: number;
  alpha: number;
  note: string;
} {
  const s1 = sk1Observations.map((o) => o.inferredIterations);
  const s2 = sk2Observations.map((o) => o.inferredIterations);

  if (s1.length === 0 || s2.length === 0) {
    return {
      exceedsCritical: false,
      ksStatistic: 0,
      criticalValue: 0,
      alpha: 0.05,
      note: 'Insufficient observations for KS test.',
    };
  }

  const alpha = 0.05;
  const stat = ksStatistic(s1, s2);
  const crit = ksCriticalValue(s1.length, s2.length, alpha);
  const exceedsCritical = stat > crit;

  return {
    exceedsCritical,
    ksStatistic: stat,
    criticalValue: crit,
    alpha,
    note: exceedsCritical
      ? `KS=${stat.toFixed(4)} exceeds the alpha=${alpha} critical value (${crit.toFixed(4)}). Under H0 (same distribution) this happens ~${Math.round(alpha * 100)}% of runs by chance.`
      : `KS=${stat.toFixed(4)} is below the alpha=${alpha} critical value (${crit.toFixed(4)}). No evidence the two populations differ.`,
  };
}
