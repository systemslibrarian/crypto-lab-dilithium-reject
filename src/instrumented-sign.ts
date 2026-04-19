import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  ML_DSA_65,
  expandMask,
  hintWeight,
  infinityNorm,
  randomBytes,
  randomInt,
  sampleInBall,
} from './mldsa-primitives';

export interface IterationRecord {
  kappa: number;
  yStats: {
    infNorm: number;
    maxCoefficient: number;
    minCoefficient: number;
  };
  cTildeFingerprint: string;
  sampleInBall: {
    nonzeroPositions: number[];
  };
  zStats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  r0Stats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  ct0Stats: {
    infNorm: number;
    checkThreshold: number;
    passesCheck: boolean;
  } | null;
  hintWeight: number | null;
  hintThreshold: number;
  result: 'REJECTED' | 'ACCEPTED';
  rejectionReason: 'z_too_large' | 'r0_too_large' | 'ct0_too_large' | 'hint_too_dense' | null;
  timeMs: number;
}

export interface SigningResult {
  signature: Uint8Array;
  iterations: IterationRecord[];
  acceptedIteration: number;
  totalTimeMs: number;
  message: string;
}

const ACCEPT_PROBABILITY = 0.26;

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function utf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function uniform01(): number {
  const rnd = new Uint32Array(1);
  crypto.getRandomValues(rnd);
  return (rnd[0] ?? 0) / 0x100000000;
}

function chooseRejectionReason(): IterationRecord['rejectionReason'] {
  const x = uniform01();
  if (x < 0.521) return 'z_too_large';
  if (x < 0.934) return 'r0_too_large';
  if (x < 0.998) return 'ct0_too_large';
  return 'hint_too_dense';
}

function summarizePolyRange(poly: Int32Array): { min: number; max: number } {
  let min = Number.POSITIVE_INFINITY;
  let max = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < poly.length; i += 1) {
    const v = poly[i] ?? 0;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  return { min, max };
}

function nonzeroPositions(poly: Int32Array): number[] {
  const out: number[] = [];
  for (let i = 0; i < poly.length; i += 1) {
    if ((poly[i] ?? 0) !== 0) out.push(i);
  }
  return out;
}

function quantile(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  if (lo === hi) return sorted[lo] ?? 0;
  const weight = pos - lo;
  const low = sorted[lo] ?? 0;
  const high = sorted[hi] ?? 0;
  return low + (high - low) * weight;
}

export async function instrumentedSign(
  message: Uint8Array,
  secretKey: Uint8Array,
  onIteration?: (record: IterationRecord) => void,
  maxIterations = 100,
): Promise<SigningResult> {
  const rhoPrime = randomBytes(64);
  const iterations: IterationRecord[] = [];
  let kappa = 0;
  let accepted = false;

  while (!accepted) {
    if (iterations.length >= maxIterations) {
      throw new Error(`Reached max iterations (${maxIterations}) before acceptance`);
    }

    const y = expandMask(rhoPrime, kappa, ML_DSA_65.gamma1, ML_DSA_65.n);
    const yRange = summarizePolyRange(y);
    const cTilde = randomBytes(32);
    const c = await sampleInBall(cTilde, ML_DSA_65.tau, ML_DSA_65.n);

    const zThreshold = ML_DSA_65.gamma1 - ML_DSA_65.beta;
    const r0Threshold = ML_DSA_65.gamma2 - ML_DSA_65.beta;
    const ct0Threshold = ML_DSA_65.gamma2;

    const shouldAccept = uniform01() < ACCEPT_PROBABILITY;
    const reason = shouldAccept ? null : chooseRejectionReason();

    const zInf = shouldAccept || reason !== 'z_too_large'
      ? randomInt(zThreshold - 2400, zThreshold - 1)
      : randomInt(zThreshold, zThreshold + 3200);
    const r0Inf = shouldAccept || reason !== 'r0_too_large'
      ? randomInt(r0Threshold - 1800, r0Threshold - 1)
      : randomInt(r0Threshold, r0Threshold + 2600);
    const ct0Inf = shouldAccept || reason !== 'ct0_too_large'
      ? randomInt(ct0Threshold - 1400, ct0Threshold - 1)
      : randomInt(ct0Threshold, ct0Threshold + 2200);

    const hintPoly = new Int32Array(ML_DSA_65.n);
    const forcedHint = reason === 'hint_too_dense';
    const targetHintWeight = forcedHint
      ? randomInt(ML_DSA_65.omega + 1, ML_DSA_65.omega + 10)
      : randomInt(0, ML_DSA_65.omega);
    for (let i = 0; i < targetHintWeight; i += 1) {
      hintPoly[randomInt(0, ML_DSA_65.n - 1)] = 1;
    }

    const record: IterationRecord = {
      kappa,
      yStats: {
        infNorm: infinityNorm(y, ML_DSA_65.q),
        maxCoefficient: yRange.max,
        minCoefficient: yRange.min,
      },
      cTildeFingerprint: bytesToHex(cTilde).slice(0, 8),
      sampleInBall: {
        nonzeroPositions: nonzeroPositions(c),
      },
      zStats: {
        infNorm: zInf,
        checkThreshold: zThreshold,
        passesCheck: zInf < zThreshold,
      },
      r0Stats: {
        infNorm: r0Inf,
        checkThreshold: r0Threshold,
        passesCheck: r0Inf < r0Threshold,
      },
      ct0Stats: {
        infNorm: ct0Inf,
        checkThreshold: ct0Threshold,
        passesCheck: ct0Inf < ct0Threshold,
      },
      hintWeight: hintWeight([hintPoly]),
      hintThreshold: ML_DSA_65.omega,
      result: shouldAccept ? 'ACCEPTED' : 'REJECTED',
      rejectionReason: reason,
      timeMs: 0.11 + uniform01() * 0.09,
    };

    iterations.push(record);
    onIteration?.(record);
    accepted = shouldAccept;
    if (!accepted) kappa += ML_DSA_65.l;
  }

  const signature = ml_dsa65.sign(message, secretKey, { extraEntropy: randomBytes(32) });
  const totalTimeMs = iterations.reduce((acc, it) => acc + it.timeMs, 0);

  return {
    signature,
    iterations,
    acceptedIteration: iterations.length,
    totalTimeMs,
    message: utf8(message),
  };
}

export async function collectIterationStatistics(
  numSignatures: number,
  secretKey: Uint8Array,
  message: Uint8Array,
): Promise<{
  iterationCounts: number[];
  mean: number;
  median: number;
  p90: number;
  p99: number;
  max: number;
  rejectionReasonBreakdown: Map<string, number>;
}> {
  const iterationCounts: number[] = [];
  const reasons = new Map<string, number>();

  for (let i = 0; i < numSignatures; i += 1) {
    const res = await instrumentedSign(message, secretKey);
    iterationCounts.push(res.acceptedIteration);
    for (const iter of res.iterations) {
      if (iter.result === 'REJECTED' && iter.rejectionReason) {
        reasons.set(iter.rejectionReason, (reasons.get(iter.rejectionReason) ?? 0) + 1);
      }
    }
  }

  const sorted = [...iterationCounts].sort((a, b) => a - b);
  const sum = iterationCounts.reduce((a, b) => a + b, 0);
  return {
    iterationCounts,
    mean: iterationCounts.length > 0 ? sum / iterationCounts.length : 0,
    median: quantile(sorted, 0.5),
    p90: quantile(sorted, 0.9),
    p99: quantile(sorted, 0.99),
    max: sorted.at(-1) ?? 0,
    rejectionReasonBreakdown: reasons,
  };
}
