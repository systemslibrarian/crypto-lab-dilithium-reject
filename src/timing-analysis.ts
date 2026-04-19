import { instrumentedSign } from './instrumented-sign';

export interface TimingObservation {
  signatureIndex: number;
  observedTimeMs: number;
  inferredIterations: number;
}

function uniform01(): number {
  const rnd = new Uint32Array(1);
  crypto.getRandomValues(rnd);
  return (rnd[0] ?? 0) / 0x100000000;
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
  secretKey: Uint8Array,
  messages: Uint8Array[],
): Promise<TimingObservation[]> {
  if (messages.length === 0) throw new Error('messages must not be empty');

  const observations: TimingObservation[] = [];
  for (let i = 0; i < numSignatures; i += 1) {
    const msg = messages[i % messages.length] ?? messages[0];
    const result = await instrumentedSign(msg, secretKey);
    const noise = (uniform01() - 0.5) * 0.06;
    const observedTimeMs = Math.max(0, result.totalTimeMs + noise);

    observations.push({
      signatureIndex: i,
      observedTimeMs,
      inferredIterations: result.acceptedIteration,
    });
  }
  return observations;
}

export function distinguishabilityTest(
  sk1Observations: TimingObservation[],
  sk2Observations: TimingObservation[],
): {
  distinguishable: boolean;
  confidenceLevel: number;
  ksStatistic: number;
  note: string;
} {
  const s1 = sk1Observations.map((o) => o.inferredIterations);
  const s2 = sk2Observations.map((o) => o.inferredIterations);

  if (s1.length === 0 || s2.length === 0) {
    return {
      distinguishable: false,
      confidenceLevel: 0,
      ksStatistic: 0,
      note: 'Insufficient observations for KS test.',
    };
  }

  const stat = ksStatistic(s1, s2);
  const crit = ksCriticalValue(s1.length, s2.length, 0.05);
  const distinguishable = stat > crit;

  return {
    distinguishable,
    confidenceLevel: distinguishable ? 0.95 : 0.05,
    ksStatistic: stat,
    note: distinguishable
      ? 'Distributions appear statistically different at alpha=0.05.'
      : 'Cannot distinguish key timing distributions at alpha=0.05.',
  };
}
